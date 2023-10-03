const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const ethUtil = require('ethereumjs-util');
const sigUtil = require('eth-sig-util');
const jwt = require('jsonwebtoken');
const path = require('path'); // Required for file paths

app.use(bodyParser.json());

// Replace this with your own secret key (used to sign JWT tokens)
const secretKey = 'w87LqcTUMeA7U8v@#yEEZX2KfH@G9mWxxx';

// Mock user database (you should use a real database)
const users = [];
const profiles= [];

// Middleware to verify MetaMask signature
function verifySignature(req, res, next) {
    const {address, signature, message} = req.body;

    const senderAddress = sigUtil.recoverPersonalSignature({
        data: message,
        sig: signature,
    });
    if (senderAddress.toLowerCase() === address.toLowerCase()) {
        // add the user to the DB, if its not there already
        if (!users.includes(senderAddress.toLowerCase())) {
            // Add the user 'Bob' to the array.
            users.push(senderAddress.toLowerCase());
        }

        // Signature is valid
        req.senderAddress = senderAddress;
        return next();
    } else {
        return res.status(401).json({error: 'Invalid signature'});
    }
}

// Route for handling MetaMask login
app.post('/login', verifySignature, (req, res) => {
    const {senderAddress} = req;

    // Check if the user is already registered

    if (users.includes(senderAddress.toLowerCase())) {
        // User exists, generate a JWT token (you should use a real authentication library)
        const token = generateAuthToken(senderAddress);
        // Check to see if the sender address is a known profile.
        let profile;
        const matchingProfile = profiles.find(obj => obj.address === senderAddress);
        if(matchingProfile) profile = { firstName, lastName, email } = matchingProfile;
        return res.status(200).json({token, profile});
        //return res.json({ token });
    } else {
        // User is not registered, you may choose to register them
        return res.status(401).json({error: 'User not registered'});
    }
});


async function verifyJwtToken(req, res) {
    const authorizationHeader = req.headers.authorization;

    if (!authorizationHeader) return res.status(401).json({error: 'Authorization header missing'});

    const tokenParts = authorizationHeader.split(' ');

    if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
        return res.status(401).json({error: 'Invalid Authorization header format'});
    }

    const jwtToken = tokenParts[1];
    let decoded;
    try {
        decoded = await jwt.verify(jwtToken, secretKey);
    } catch (e) {
        return res.status(401).json({error: e.message});
    }
        // Access decoded data (user information)
    const userData = decoded;

        // Process the data as needed
    console.log('Decoded User Data:', userData);
    return userData
}
// Route for handling MetaMask login
app.post('/profile', async (req, res) => {
    const tokenData = await verifyJwtToken(req, res)

    // Check if the user is already registered

    if (users.includes(tokenData.senderAddress.toLowerCase())) {
        const {firstName, lastName, email} = req.body;
        if (!profiles.some(obj => obj.address === tokenData.senderAddress)){
            profiles.push({
                address: tokenData.senderAddress,
                firstName,
                lastName,
                email
            })
            return res.status(200).json("ok");
        }else{
            return res.status(201).json("ok");;
        }
    } else {
        // User is not registered, you may choose to register them
        return res.status(401).json({error: 'Invalid authentication'});
    }
});

// Helper function to generate a JWT token (replace with your own token generation logic)
function generateAuthToken(senderAddress) {
    const token = jwt.sign({senderAddress}, secretKey, {expiresIn: '1h'});
    return `Bearer ${token}`;
}

// Serve static files from the 'public' folder
app.use(express.static(path.join(__dirname, 'public')));

// Define a route to serve the 'index.html' file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3111;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
