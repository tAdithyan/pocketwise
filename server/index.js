const express = require("express");
const cors = require("cors");
const crypto = require("node:crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const store = require("./store");
const { connect, read, write } = store;
const app = express();
app.use(cors());
app.use(express.json());
const port = Number(process.env.PORT) || 3001;
const jwtSecret = process.env.JWT_SECRET || "";
function syncLoanStatus(loan, completedDate) {
  if (loan.totalPayable != null && Number(loan.paid) >= Number(loan.totalPayable)) {
    loan.status = "COMPLETED";
    loan.completedDate = loan.completedDate || completedDate || loan.startDate;
  } else {
    loan.status = "ACTIVE";
    delete loan.completedDate;
  }
}
app.get("/api/health", (_, res) => res.json({ ok: true }));
function makeToken(user) {
  return jwt.sign({ email: user.email }, jwtSecret, { subject: user._id, expiresIn: "30d" });
}
app.post("/api/auth/register", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: "Enter a valid email address." });
  if (password.length < 8 || password.length > 128)
    return res.status(400).json({ error: "Password must be between 8 and 128 characters." });
  const user = { _id: crypto.randomUUID(), email, passwordHash: await bcrypt.hash(password, 12), createdAt: new Date() };
  try {
    await store.users.insertOne(user);
  } catch (error) {
    if (error.code === 11000) return res.status(409).json({ error: "An account with this email already exists." });
    throw error;
  }
  await read(user._id);
  res.status(201).json({ token: makeToken(user), user: { email: user.email } });
});
app.post("/api/auth/login", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = await store.users.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ error: "Invalid email or password." });
  res.json({ token: makeToken(user), user: { email: user.email } });
});
function requireAuth(req, res, next) {
  const [scheme, token] = String(req.headers.authorization || "").split(" ");
  if (scheme !== "Bearer" || !token) return res.status(401).json({ error: "Sign in to continue." });
  try {
    const payload = jwt.verify(token, jwtSecret);
    if (!payload.sub) throw new Error("Missing token subject");
    req.user = { id: payload.sub, email: payload.email };
    next();
  } catch {
    res.status(401).json({ error: "Your session is invalid or expired. Please sign in again." });
  }
}
app.use("/api", (req, res, next) => {
  if (req.path === "/health" || req.path === "/auth/register" || req.path === "/auth/login") return next();
  return requireAuth(req, res, next);
});
app.get("/api/data", async (req, res) => res.json(await read(req.user.id)));
app.post("/api/transactions", async (req, res) => {
  const d = await read(req.user.id),
    x = req.body;
  if (
    ![
      "INCOME",
      "EXPENSE",
      "PAYMENT",
      "EMI_PAYMENT",
      "EXTRA_LOAN_PAYMENT",
    ].includes(x.type) ||
    !Number.isFinite(+x.amount) ||
    +x.amount <= 0 ||
    !x.date
  )
    return res.status(400).json({ error: "Enter a valid amount and date." });
  const row = { ...x, id: crypto.randomUUID(), amount: +x.amount };
  d.transactions.unshift(row);
  await write(d, req.user.id);
  res.status(201).json(row);
});
app.delete("/api/transactions/:id", async (req, res) => {
  const d = await read(req.user.id),
    i = d.transactions.findIndex((x) => x.id === req.params.id);
  if (i < 0) return res.sendStatus(404);
  const [row] = d.transactions.splice(i, 1);
  if (row.monthlyPaymentId) {
    const p = d.payments.find((x) => x.id === row.monthlyPaymentId);
    if (p) {
      const entry = Object.entries(p.instances || {}).find(
        ([, v]) => v.transactionId === row.id,
      );
      if (entry) delete p.instances[entry[0]];
    }
  }
  if (row.loanId) {
    const loan = d.loans.find((x) => x.id === row.loanId);
    if (loan) {
      loan.paid = Math.max(0, loan.paid - Number(row.amount));
      loan.paidEmis = Math.max(0, loan.paidEmis - 1);
      syncLoanStatus(loan);
    }
  }
  await write(d, req.user.id);
  res.json(row);
});
app.post("/api/payments", async (req, res) => {
  const d = await read(req.user.id),
    x = req.body;
  if (!x.name || !x.dueDay)
    return res
      .status(400)
      .json({ error: "Payment name and due day are required." });
  const row = {
    ...x,
    id: crypto.randomUUID(),
    expectedAmount:
      x.expectedAmount === "" || x.expectedAmount == null
        ? null
        : Number(x.expectedAmount),
    recurring: x.recurring !== false,
    instances: {},
  };
  d.payments.push(row);
  await write(d, req.user.id);
  res.status(201).json(row);
});
app.delete("/api/payments/:id/instances/:month", async (req, res) => {
  const d = await read(req.user.id),
    p = d.payments.find((x) => x.id === req.params.id),
    month = req.params.month;
  if (!p) return res.sendStatus(404);
  if (!/^\d{4}-\d{2}$/.test(month))
    return res.status(400).json({ error: "Invalid payment month." });
  const instance = p.instances?.[month];
  if (instance?.transactionId) {
    d.transactions = d.transactions.filter(
      (t) => t.id !== instance.transactionId,
    );
    if (p.loanId) {
      const loan = d.loans.find((x) => x.id === p.loanId);
      if (loan) {
        loan.paid = Math.max(0, loan.paid - Number(instance.amount || 0));
        loan.paidEmis = Math.max(0, loan.paidEmis - 1);
        syncLoanStatus(loan);
      }
    }
  }
  p.instances = p.instances || {};
  p.instances[month] = { status: "SKIPPED" };
  await write(d, req.user.id);
  res.json({ deleted: true, month, otherMonthsPreserved: true });
});
app.post("/api/payments/:id/paid", async (req, res) => {
  const d = await read(req.user.id),
    p = d.payments.find((x) => x.id === req.params.id),
    { month, amount, date, method } = req.body;
  if (!p) return res.sendStatus(404);
  if (!/^\d{4}-\d{2}$/.test(month) || !Number.isFinite(+amount) || +amount <= 0)
    return res.status(400).json({ error: "Enter a valid amount." });
  if (p.instances[month]?.status === "PAID")
    return res.status(409).json({ error: "This payment is already recorded." });
  if (p.loanId) {
    const loan = d.loans.find((x) => x.id === p.loanId);
    if (
      loan?.totalPayable != null &&
      Number(loan.paid) >= Number(loan.totalPayable)
    )
      return res.status(409).json({ error: "This loan is already completed." });
  }
  const tx = {
    id: crypto.randomUUID(),
    type: p.loanId ? "EMI_PAYMENT" : "EXPENSE",
    amount: +amount,
    date: date || `${month}-15`,
    category: p.category,
    merchant: p.name,
    method: method || "UPI",
    monthlyPaymentId: p.id,
    loanId: p.loanId || null,
  };
  p.instances[month] = {
    status: "PAID",
    amount: +amount,
    date: tx.date,
    method: tx.method,
    transactionId: tx.id,
  };
  d.transactions.unshift(tx);
  if (p.loanId) {
    const loan = d.loans.find((x) => x.id === p.loanId);
    if (loan) {
      loan.paid += +amount;
      loan.paidEmis += 1;
      syncLoanStatus(loan, tx.date);
    }
  }
  await write(d, req.user.id);
  res.status(201).json({ payment: p, transaction: tx });
});
app.post("/api/payments/:id/undo", async (req, res) => {
  const d = await read(req.user.id),
    p = d.payments.find((x) => x.id === req.params.id),
    month = req.body.month,
    instance = p?.instances?.[month];
  if (!instance || instance.status !== "PAID")
    return res.status(404).json({ error: "No paid record found." });
  d.transactions = d.transactions.filter(
    (t) => t.id !== instance.transactionId,
  );
  if (p.loanId) {
    const loan = d.loans.find((x) => x.id === p.loanId);
    if (loan) {
      loan.paid = Math.max(0, loan.paid - instance.amount);
      loan.paidEmis = Math.max(0, loan.paidEmis - 1);
      syncLoanStatus(loan);
    }
  }
  delete p.instances[month];
  await write(d, req.user.id);
  res.json({ ok: true });
});
app.post("/api/loans", async (req, res) => {
  const d = await read(req.user.id),
    x = req.body;
  if (!x.name || !Number.isFinite(+x.monthlyEmi) || +x.monthlyEmi <= 0)
    return res
      .status(400)
      .json({ error: "Name and monthly EMI are required." });
  const row = {
    ...x,
    id: crypto.randomUUID(),
    principal: +x.principal || 0,
    monthlyEmi: +x.monthlyEmi,
    totalPayable: x.totalPayable ? +x.totalPayable : null,
    paid: 0,
    paidEmis: 0,
    tenureMonths: x.tenureMonths ? +x.tenureMonths : null,
  };
  d.loans.push(row);
  d.payments.push({
    id: crypto.randomUUID(),
    name: row.name,
    category: "Loan",
    expectedAmount: row.monthlyEmi,
    dueDay: Number(x.dueDay) || 5,
    startDate: x.startDate || new Date().toISOString().slice(0, 10),
    recurring: true,
    loanId: row.id,
    instances: {},
  });
  await write(d, req.user.id);
  res.status(201).json(row);
});
app.patch("/api/loans/:id", async (req, res) => {
  const d = await read(req.user.id);
  const loan = d.loans.find((item) => item.id === req.params.id);
  if (!loan) return res.sendStatus(404);
  const { name, lender, principal, monthlyEmi, totalPayable, annualRate, tenureMonths, startDate, dueDay } = req.body;
  if (!name?.trim() || !Number.isFinite(Number(monthlyEmi)) || Number(monthlyEmi) <= 0)
    return res.status(400).json({ error: "Name and a positive monthly EMI are required." });
  if (principal !== "" && principal != null && (!Number.isFinite(Number(principal)) || Number(principal) < 0))
    return res.status(400).json({ error: "Enter a valid principal amount." });
  if (totalPayable !== "" && totalPayable != null && (!Number.isFinite(Number(totalPayable)) || Number(totalPayable) < 0))
    return res.status(400).json({ error: "Enter a valid total payable amount." });
  Object.assign(loan, {
    name: name.trim(), lender: lender?.trim() || "", principal: Number(principal) || 0,
    monthlyEmi: Number(monthlyEmi), totalPayable: totalPayable === "" || totalPayable == null ? null : Number(totalPayable),
    annualRate: annualRate === "" || annualRate == null ? null : Number(annualRate),
    tenureMonths: tenureMonths === "" || tenureMonths == null ? null : Number(tenureMonths),
  });
  if (startDate) loan.startDate = startDate;
  syncLoanStatus(loan);
  const payment = d.payments.find((item) => item.loanId === loan.id);
  if (payment) {
    payment.name = loan.name;
    payment.expectedAmount = loan.monthlyEmi;
    payment.dueDay = Math.min(31, Math.max(1, Number(dueDay) || payment.dueDay || 5));
    payment.startDate = loan.startDate || payment.startDate;
  }
  await write(d, req.user.id);
  res.json(loan);
});
app.delete("/api/loans/:id", async (req, res) => {
  const d = await read(req.user.id);
  const loan = d.loans.find((item) => item.id === req.params.id);
  if (!loan) return res.sendStatus(404);
  const paymentIds = d.payments.filter((item) => item.loanId === loan.id).map((item) => item.id);
  d.payments = d.payments.filter((item) => item.loanId !== loan.id);
  d.transactions = d.transactions.filter((item) => item.loanId !== loan.id && !paymentIds.includes(item.monthlyPaymentId));
  d.loans = d.loans.filter((item) => item.id !== loan.id);
  await write(d, req.user.id);
  res.json({ deleted: true });
});
app.patch("/api/payments/:id", async (req, res) => {
  const d = await read(req.user.id);
  const payment = d.payments.find((item) => item.id === req.params.id);
  if (!payment) return res.sendStatus(404);
  const { name, expectedAmount, dueDay, startDate } = req.body;
  const amount = expectedAmount === "" || expectedAmount == null ? null : Number(expectedAmount);
  const day = Number(dueDay);
  if (!name?.trim() || (amount != null && (!Number.isFinite(amount) || amount < 0)) || !Number.isInteger(day) || day < 1 || day > 31 || !/^\d{4}-\d{2}-\d{2}$/.test(startDate || ""))
    return res.status(400).json({ error: "Enter a name, valid amount, due day, and start date." });
  Object.assign(payment, { name: name.trim(), expectedAmount: amount, dueDay: day, startDate });
  const loan = d.loans.find((item) => item.id === payment.loanId);
  if (loan) Object.assign(loan, { name: payment.name, monthlyEmi: amount ?? loan.monthlyEmi, startDate });
  await write(d, req.user.id);
  res.json(payment);
});
app.delete("/api/payments/:id", async (req, res) => {
  const d = await read(req.user.id);
  const payment = d.payments.find((item) => item.id === req.params.id);
  if (!payment) return res.sendStatus(404);
  d.payments = d.payments.filter((item) => item.id !== payment.id);
  await write(d, req.user.id);
  res.json({ deleted: true, historyPreserved: true });
});
app.post("/api/budgets", async (req, res) => {
  const d = await read(req.user.id),
    x = req.body;
  if (!x.category || !Number.isFinite(+x.limit) || +x.limit <= 0)
    return res
      .status(400)
      .json({ error: "Category and positive budget required." });
  let b = d.budgets.find((v) => v.category === x.category);
  if (b) b.limit = +x.limit;
  else
    d.budgets.push({
      id: crypto.randomUUID(),
      category: x.category,
      limit: +x.limit,
    });
  await write(d, req.user.id);
  res.json(b || d.budgets.at(-1));
});
app.use((error, _req, res, _next) => {
  console.error("API request failed:", error.name || "Error");
  res.status(500).json({ error: "Request could not be completed." });
});
async function start() {
  if (jwtSecret.length < 32) throw new Error("JWT_SECRET must be at least 32 characters");
  await connect();
  app.listen(port, "0.0.0.0", () => console.log(`Pocketwise API listening on ${port} with MongoDB`));
}
start().catch((error) => {
  console.error("MongoDB connection failed. Check MONGODB_URI and Atlas network access.", error.name);
  process.exit(1);
});
