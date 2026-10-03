const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { MongoClient } = require("mongodb");

const legacyFile = path.join(__dirname, "data.json");
const client = new MongoClient(process.env.MONGODB_URI || "", {
  serverSelectionTimeoutMS: 10000,
});
let collection;
let usersCollection;
let migrationsCollection;
const initialized = new Map();

async function connect() {
  if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI is missing");
  await client.connect();
  const db = client.db(process.env.MONGODB_DATABASE || "pocketwise");
  collection = db.collection("app_state");
  usersCollection = db.collection("users");
  migrationsCollection = db.collection("auth_migrations");
  await usersCollection.createIndex({ email: 1 }, { unique: true });
}

function migrateLegacyData(data) {
  data.transactions = Array.isArray(data.transactions) ? data.transactions : [];
  data.payments = Array.isArray(data.payments) ? data.payments : [];
  data.loans = Array.isArray(data.loans) ? data.loans : [];
  data.budgets = Array.isArray(data.budgets) ? data.budgets : [];
  data.goals = Array.isArray(data.goals) ? data.goals : [];
  for (const payment of data.payments) {
    payment.instances ||= {};
    for (const transaction of data.transactions) {
      if (transaction.monthlyPaymentId !== payment.id || !transaction.date) continue;
      const month = transaction.date.slice(0, 7);
      if (!payment.instances[month]) payment.instances[month] = {
        status: "PAID", amount: Number(transaction.amount), date: transaction.date,
        method: transaction.method || "UPI", transactionId: transaction.id,
      };
    }
  }
  for (const loan of data.loans) {
    if (!data.payments.some((payment) => payment.loanId === loan.id)) {
      const startDate = loan.startDate || new Date().toISOString().slice(0, 10);
      data.payments.push({
        id: crypto.randomUUID(), name: loan.name, category: "Loan",
        expectedAmount: Number(loan.monthlyEmi), dueDay: Number(startDate.slice(8, 10)) || 5,
        startDate, recurring: true, loanId: loan.id, instances: {},
      });
    }
  }
  return data;
}

async function initialize(userId) {
  if (!collection) throw new Error("MongoDB is not connected");
  let state = await collection.findOne({ _id: userId });
  if (!state) {
    // The first account claims the existing single-user data once; each later
    // account receives a separate empty state document.
    const claim = await migrationsCollection.findOneAndUpdate(
      { _id: "legacy-local-user" },
      { $setOnInsert: { userId, claimedAt: new Date() } },
      { upsert: true, returnDocument: "after" },
    );
    if (claim?.userId === userId) {
      let legacy = await collection.findOne({ _id: "local-user" });
      if (!legacy && fs.existsSync(legacyFile)) {
        let data = migrateLegacyData(JSON.parse(fs.readFileSync(legacyFile, "utf8")));
        legacy = { _id: "local-user", ...data };
      }
      if (legacy) {
        const { _id, updatedAt, ...data } = legacy;
        await collection.updateOne({ _id: userId }, { $setOnInsert: { _id: userId, ...data, updatedAt: new Date() } }, { upsert: true });
        await collection.deleteOne({ _id: "local-user" });
        state = await collection.findOne({ _id: userId });
      }
    }
    if (!state) {
      const empty = { _id: userId, transactions: [], payments: [], loans: [], budgets: [], goals: [], updatedAt: new Date() };
      await collection.updateOne({ _id: userId }, { $setOnInsert: empty }, { upsert: true });
      state = await collection.findOne({ _id: userId });
    }
  }
  return state;
}

async function read(userId) {
  if (!userId) throw new Error("An authenticated user is required");
  if (!initialized.has(userId)) {
    const pending = initialize(userId);
    initialized.set(userId, pending);
    try { await pending; } catch (error) { initialized.delete(userId); throw error; }
  }
  const { _id, updatedAt, ...data } = await collection.findOne({ _id: userId });
  return structuredClone(data);
}

async function write(data, userId) {
  if (!collection) throw new Error("MongoDB is not connected");
  if (!userId) throw new Error("An authenticated user is required");
  const fields = { ...data };
  await collection.replaceOne(
    { _id: userId },
    { _id: userId, ...fields, updatedAt: new Date() },
    { upsert: true },
  );
}

module.exports = { connect, read, write, get users() { return usersCollection; } };
