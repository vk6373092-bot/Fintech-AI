require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');

const app = express();

console.log("🔥 CORRECT SERVER RUNNING");

// ================== MIDDLEWARE ==================

// Allow both 3000 and 5500 just in case you switch between Live Server and React/Node
app.use(cors({
    origin: ["http://localhost:3000", "http://127.0.0.1:5500", "http://localhost:5500"],
    credentials: true
}));

app.use(express.json());

// 🔥 SESSION (IMPORTANT)
app.use(session({
    secret: process.env.JWT_SECRET || "mysecret123",
    resave: false,
    saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

// ================== DATABASE CONNECTION ==================

mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// ================== DATABASE SCHEMAS ==================

// 1. User
const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
    googleId: String
});
const User = mongoose.model('User', userSchema);

// 2. Transactions (Dashboard & Analytics)
const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true },
    description: { type: String, required: true },
    category: { type: String, required: true },
    type: { type: String, enum: ['income', 'expense', 'Income', 'Expense'], required: true },
    date: { type: Date, default: Date.now }
});
const Transaction = mongoose.model('Transaction', transactionSchema);

// 3. Portfolio Assets (Portfolio & X-Ray)
const portfolioSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    assetName: { type: String, required: true },
    category: { type: String, required: true }, 
    investedAmount: { type: Number, required: true },
    currentValue: { type: Number, required: true },
    dateAdded: { type: Date, default: Date.now }
});
const PortfolioAsset = mongoose.model('PortfolioAsset', portfolioSchema);

// 4. Life Events 
const lifeEventSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    eventName: { type: String, required: true },
    targetAmount: { type: Number, required: true },
    targetDate: { type: Date, required: true },
    savedAmount: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});
const LifeEvent = mongoose.model('LifeEvent', lifeEventSchema);

// 5. AI Chat History
const chatHistorySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    message: { type: String, required: true },
    sender: { type: String, enum: ['user', 'ai'], required: true },
    timestamp: { type: Date, default: Date.now }
});
const ChatHistory = mongoose.model('ChatHistory', chatHistorySchema);

// 6. Master Snapshot (Health, Tax, FIRE, Couple)
const userSnapshotSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    healthData: { type: Object, default: {} },
    fireData: { type: Object, default: {} },
    taxData: { type: Object, default: {} },
    coupleData: { type: Object, default: {} },
    lastUpdated: { type: Date, default: Date.now }
});
const UserSnapshot = mongoose.model('UserSnapshot', userSnapshotSchema);

// ================== PASSPORT SESSION ==================

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    const user = await User.findById(id);
    done(null, user);
});

// ================== LOCAL AUTH ==================

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const existing = await User.findOne({ $or: [{ email }, { username }] });
        if (existing) return res.status(400).json({ message: 'User already exists' });

        const hash = await bcrypt.hash(password, 10);
        await User.create({ username, email, password: hash });
        res.json({ message: 'Registered successfully' });
    } catch {
        res.status(500).json({ message: 'Error' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { usernameOrEmail, password } = req.body;
        const user = await User.findOne({
            $or: [{ email: usernameOrEmail }, { username: usernameOrEmail }]
        });

        if (!user || !user.password) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ message: 'Invalid credentials' });

        // FIXED: Using userId so it matches your middleware
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
        res.json({ token });
    } catch {
        res.status(500).json({ message: 'Error' });
    }
});

// ================== GOOGLE AUTH ==================

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:5000/api/auth/google/callback"
},
async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
            user = await User.findOne({ email: profile.emails[0].value });
            if (user) {
                user.googleId = profile.id;
                await user.save();
            } else {
                user = await User.create({
                    username: profile.displayName,
                    email: profile.emails[0].value,
                    googleId: profile.id
                });
            }
        }
        return done(null, user);
    } catch (err) {
        return done(err, null);
    }
}));

app.get('/api/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/api/auth/google/callback',
    passport.authenticate('google', { failureRedirect: 'http://localhost:3000/login.html' }),
    (req, res) => {
        // FIXED: Using userId so it matches your middleware
        const token = jwt.sign({ userId: req.user._id }, process.env.JWT_SECRET);
        res.redirect(`http://localhost:3000/index.html?token=${token}`);
    }
);

// ==========================================
// MIDDLEWARE: Protect Routes with JWT
// ==========================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Access Denied. No token provided.' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired token.' });
        req.user = user; 
        next();
    });
};

// ==========================================
// APP DATA ROUTES (Protected)
// ==========================================

// --- TRANSACTIONS (Dashboard) ---

// 1. Save a new transaction
app.post('/api/transactions', authenticateToken, async (req, res) => {
    try {
        const activeUserId = req.user.userId || req.user.id; 
        if (!activeUserId) return res.status(400).json({ message: 'User ID missing' });

        const newTx = new Transaction({ userId: activeUserId, ...req.body });
        await newTx.save();
        res.status(201).json({ message: 'Transaction saved', transaction: newTx });
    } catch (err) { 
        console.error("Save Error:", err);
        res.status(500).json({ message: 'Failed to save transaction' }); 
    }
});

// 2. Fetch history and balance
app.get('/api/transactions', authenticateToken, async (req, res) => {
    try {
        const activeUserId = req.user.userId || req.user.id;
        const transactions = await Transaction.find({ userId: activeUserId }).sort({ date: -1 });
        res.status(200).json(transactions);
    } catch (err) { 
        res.status(500).json({ message: 'Failed to fetch transactions' }); 
    }
});

// 3. Delete a transaction
app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
    try {
        const activeUserId = req.user.userId || req.user.id;
        await Transaction.findOneAndDelete({ _id: req.params.id, userId: activeUserId });
        res.status(200).json({ message: 'Transaction deleted' });
    } catch (err) { 
        res.status(500).json({ message: 'Failed to delete' }); 
    }
});

// --- PORTFOLIO ASSETS ---
app.post('/api/portfolio', authenticateToken, async (req, res) => {
    try {
        const asset = new PortfolioAsset({ userId: req.user.userId, ...req.body });
        await asset.save();
        res.status(201).json(asset);
    } catch (err) { res.status(500).json({ error: 'Failed to save asset' }); }
});

app.get('/api/portfolio', authenticateToken, async (req, res) => {
    try {
        const assets = await PortfolioAsset.find({ userId: req.user.userId }).sort({ dateAdded: -1 });
        res.status(200).json(assets);
    } catch (err) { res.status(500).json({ error: 'Failed to fetch portfolio' }); }
});

app.delete('/api/portfolio/:id', authenticateToken, async (req, res) => {
    try {
        await PortfolioAsset.findOneAndDelete({ _id: req.params.id, userId: req.user.userId });
        res.status(200).json({ message: 'Asset removed' });
    } catch (err) { res.status(500).json({ error: 'Failed to delete asset' }); }
});


// --- PORTFOLIO ASSETS ---
// (Keep your POST, GET, and DELETE routes, just add this one below them)

app.put('/api/portfolio/:id', authenticateToken, async (req, res) => {
    try {
        const updatedAsset = await PortfolioAsset.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.userId },
            { $set: req.body },
            { new: true }
        );
        if (!updatedAsset) return res.status(404).json({ message: 'Asset not found' });
        res.status(200).json(updatedAsset);
    } catch (err) { 
        res.status(500).json({ error: 'Failed to update asset' }); 
    }
});
// --- LIFE EVENTS ---
app.post('/api/events', authenticateToken, async (req, res) => {
    try {
        const event = new LifeEvent({ userId: req.user.userId, ...req.body });
        await event.save();
        res.status(201).json(event);
    } catch (err) { res.status(500).json({ error: 'Failed to save event' }); }
});

app.get('/api/events', authenticateToken, async (req, res) => {
    try {
        const events = await LifeEvent.find({ userId: req.user.userId }).sort({ targetDate: 1 });
        res.status(200).json(events);
    } catch (err) { res.status(500).json({ error: 'Failed to fetch events' }); }
});

app.delete('/api/events/:id', authenticateToken, async (req, res) => {
    try {
        await LifeEvent.findOneAndDelete({ _id: req.params.id, userId: req.user.userId });
        res.status(200).json({ message: 'Event deleted' });
    } catch (err) { res.status(500).json({ error: 'Failed to delete event' }); }
});

// Function to normalize data across snapshots
async function normalizeUserData(userId, updatedType, newData) {
    const snapshot = await UserSnapshot.findOne({ userId });
    if (!snapshot) return;

    let updates = {};

    // If Salary is updated in Tax Wizard, sync it to Couple Planner and Health Diagnostics
    if (updatedType === 'taxData') {
        const salary = newData.salary;
        if (snapshot.coupleData) {
            updates['coupleData.inc1'] = salary / 12; // Update Partner A's monthly income
        }
        if (snapshot.healthData) {
            updates['healthData.income'] = salary / 12;
        }
    }

    // If Expenses are updated in Couple Planner, sync to Health Diagnostics
    if (updatedType === 'coupleData') {
        const totalBills = newData.bills;
        if (snapshot.healthData) {
            updates['healthData.expense'] = totalBills;
        }
    }

    if (Object.keys(updates).length > 0) {
        await UserSnapshot.updateOne({ userId }, { $set: updates });
    }
}

// Update your existing POST /api/snapshot to call this function
app.post('/api/snapshot', authenticateToken, async (req, res) => {
    try {
        const { type, data } = req.body;
        const updateField = {};
        updateField[type] = data;

        const snapshot = await UserSnapshot.findOneAndUpdate(
            { userId: req.user.userId },
            { $set: updateField, lastUpdated: Date.now() },
            { new: true, upsert: true }
        );

        // Run Normalization Logic
        await normalizeUserData(req.user.userId, type, data);

        res.status(200).json(snapshot);
    } catch (err) {
        res.status(500).json({ error: 'Failed to save and sync data' });
    }
});

const notificationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    title: String,
    message: String,
    type: { type: String, enum: ['warning', 'success', 'info'] },
    read: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});
const Notification = mongoose.model('Notification', notificationSchema);

// Route to get notifications
app.get('/api/notifications', authenticateToken, async (req, res) => {
    const notes = await Notification.find({ userId: req.user.userId }).sort({ createdAt: -1 }).limit(5);
    res.json(notes);
});

// Automated Trigger Example: Add this inside your normalization function
async function triggerNotifications(userId, snapshot) {
    // Example: Trigger warning if Debt is > 40% of Income
    const inc = snapshot.healthData.income;
    const debt = snapshot.healthData.debt;
    if (debt / inc > 0.4) {
        await Notification.create({
            userId,
            title: "High Debt Warning",
            message: "Your debt-to-income ratio has exceeded 40%. Consider pausing new investments.",
            type: "warning"
        });
    }
}



// --- MASTER DATA SNAPSHOTS (Health, FIRE, Tax, Couple) ---
app.post('/api/snapshot', authenticateToken, async (req, res) => {
    try {
        const { type, data } = req.body; // e.g., type: "healthData"
        const updateField = {};
        updateField[type] = data;

        const snapshot = await UserSnapshot.findOneAndUpdate(
            { userId: req.user.userId },
            { $set: updateField, lastUpdated: Date.now() },
            { new: true, upsert: true }
        );
        res.status(200).json(snapshot);
    } catch (err) { res.status(500).json({ error: 'Failed to save progress' }); }
});

app.get('/api/snapshot', authenticateToken, async (req, res) => {
    try {
        const snapshot = await UserSnapshot.findOne({ userId: req.user.userId });
        res.status(200).json(snapshot || {});
    } catch (err) { res.status(500).json({ error: 'Failed to fetch progress' }); }
});

// --- AI ADVISOR CHAT (Merged Logic) ---
app.post('/api/chat', authenticateToken, async (req, res) => {
    try {
        const { message } = req.body;
        
        // 1. Save user message to DB
        const userChat = new ChatHistory({ userId: req.user.userId, message, sender: 'user' });
        await userChat.save();

        // 2. Generate AI Response
        let aiResponse = "I am processing your request...";
        if(message.toLowerCase().includes('gold')) {
            aiResponse = "Based on live backend data, Gold is trading at ₹1,50,280 for 10 grams. I recommend allocating 5-10% in Sovereign Gold Bonds.";
        } else if (message.toLowerCase().includes('sip')) {
            aiResponse = "To reach ₹1 Crore, start a SIP of ₹15,000/month at 15% CAGR for 15 years. Check the calculator in your sidebar!";
        } else {
            aiResponse = "I have received your query: '" + message + "'. As your AI advisor, I am analyzing market trends to give you the best strategy.";
        }

        // 3. Save AI response to DB
        const aiChat = new ChatHistory({ userId: req.user.userId, message: aiResponse, sender: 'ai' });
        await aiChat.save();

        // 4. Send response back
        setTimeout(() => {
            res.status(200).json({ reply: aiResponse });
        }, 800);

    } catch (err) {
        res.status(500).json({ message: 'AI Engine failed to respond.' });
    }
});

app.get('/api/chat', authenticateToken, async (req, res) => {
    try {
        const history = await ChatHistory.find({ userId: req.user.userId }).sort({ timestamp: 1 });
        res.status(200).json(history);
    } catch (err) { res.status(500).json({ error: 'Failed to fetch chat history' }); }
});

app.delete('/api/chat', authenticateToken, async (req, res) => {
    try {
        await ChatHistory.deleteMany({ userId: req.user.userId });
        res.status(200).json({ message: 'Chat history cleared' });
    } catch (err) { res.status(500).json({ error: 'Failed to clear chat' }); }
});

// ================== TEST ROUTE ==================
app.get('/check', (req, res) => {
    res.send("✅ SERVER ACTIVE");
});

// ================== SERVER ==================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Backend running at http://localhost:${PORT}`);
});