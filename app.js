const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const crypto = require('crypto');
const cors = require('cors');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');

const app = express(); // Create an Express app

const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"],
        allowedHeaders: ["my-custom-header"],
        credentials: true
    },
    pingInterval: 10000, // send a ping every 10 seconds
    pingTimeout: 5000,
});

app.use(cors());

// Create a MySQL connection
const db = mysql.createPool({
    connectionLimit: 20, // Adjust based on your application needs
    host: 'srv1157.hstgr.io',
    user: 'u629484482_healthi_web',
    password: 'Musician_1999!!',
    database: 'u629484482_healthi',
    waitForConnections: true,
    queueLimit: 0,
    connectTimeout: 10000,//10 sec
});

const dbConfig = {
    connectionLimit: 20, // Adjust based on your application needs
    host: 'srv1157.hstgr.io',
    user: 'u629484482_healthi_web',
    password: 'Musician_1999!!',
    database: 'u629484482_healthi',
    waitForConnections: true,
    queueLimit: 0,
    connectTimeout: 10000, // 10 sec
};

function handleDisconnect() {
    db.end();
    db = mysql.createPool(dbConfig);
}

db.on('connection', (connection) => {
    console.log('Database connected:', connection.threadId);

    connection.on('error', (err) => {
        console.error('Database connection error:', err);

        if (err.code === 'PROTOCOL_CONNECTION_LOST') {
            // Connection to the MySQL server is usually lost due to a timeout.
            // Reconnect on connection lost
            handleDisconnect();
        } else {
            console.error('Database connection error:', err);
            handleDisconnect();
        }
    });
});

io.on('connection', (socket) => {
    console.log('A user connected');
    //User Verification
    socket.on('verification', async (data) => {
        const { username, password } = data;
    
        // For hashing password with Salt
        function hashPassword(password, salt) {
            const hmac = crypto.createHmac('sha256', salt);
            const hashedPassword = hmac.update(password).digest('hex');
            return hashedPassword;
        }
    
        try {
            const [results] = await db.execute('SELECT * FROM `user` WHERE `username` = ? AND `type` = "user"', [username]);
    
            if (results.length > 0) {
                const uid = results[0]['id'];
                const adminid = results[0]['admin_id'];
                const facility = results[0]['facility'];
                const storedPasswordHash = results[0]['password_hash'];
                const storedSalt = results[0]['salt'];
    
                const hashedEnteredPassword = hashPassword(password, storedSalt);
    
                if (hashedEnteredPassword === storedPasswordHash) {
                    // Password is correct
                    console.log('Authentication successful');
                    socket.emit('verificationResult', { success: true, message: 'Authentication successful', uid: uid, adminid: adminid, facility: facility });
                } else {
                    // Password is incorrect
                    console.log('Authentication failed');
                    socket.emit('verificationResult', { success: false, message: 'Authentication failed' });
                }
            } else {
                console.log('User not found');
                socket.emit('verificationResult', { success: false, message: 'User not found' });
            }
        } catch (error) {
            console.error('MySQL query error:', error);
    
            if (error.code === 'PROTOCOL_CONNECTION_LOST') {
                // Reconnect on connection lost
                try {
                    await db.connect();
                    console.log('Database reconnected');
                    // Retry the verification after successful reconnection
                    socket.emit('verification', data);
                } catch (reconnectError) {
                    console.error('Failed to reconnect to the database:', reconnectError);
                    socket.emit('verificationResult', { success: false, message: 'Failed to reconnect to the database' });
                }
            } else {
                socket.emit('verificationResult', { success: false, message: 'An unexpected error occurred' });
            }
        }
    });

    //Account Recovery Send and Insert OTP
    socket.on('retrieve_account', async (data) => {
        const { username } = data;

        //For Generate OTP
        function generateOTP() {
            return Math.floor(100000 + Math.random() * 900000).toString();
        }

        //For hashing password with Salt
        function hashPassword(password, salt) {
            const hmac = crypto.createHmac('sha256', salt);
            const hashedPassword = hmac.update(password).digest('hex');
            return hashedPassword;
        }

        const query = 'SELECT * FROM `user` WHERE `username` = ? AND `type` = "user"';
        db.query(query, [username], (err, results) => {
            if (err) {
                console.error('MySQL query error:', err);
                return;
            }
            if (results.length > 0) {
                const uid = results[0]['id'];
                const email = results[0]['email'];
                const adminid = results[0]['admin_id'];
                const facility = results[0]['facility'];

                const otp = generateOTP();
                const storedSalt = results[0]['salt'];

                const hashedOtpPassword = hashPassword(otp, storedSalt);

                const query = "UPDATE `user` SET `otp` = ? WHERE `username` = ? AND `type` = 'user'";
                var user = db.query(query, [hashedOtpPassword, username], (err, results) => {
                    if (err) {
                        console.error('MySQL query error:', err);
                        socket.emit('otpInserted', { success: false, message: err, uid: 0, email: '', username: '', adminid: 0, facility: '' });
                    }
                    else {

                        const credentials = require('./client_secret_403870755566-ljgd8srkol04uc30ag8f8bl4u0ekerpo.apps.googleusercontent.com.json');

                        console.log('Credentials:', credentials);

                        const { client_id, client_secret, redirect_uris } = credentials.web;

                        // Create an OAuth2 client
                        const oAuth2Client = new google.auth.OAuth2(
                            client_id,
                            client_secret,
                            redirect_uris[0]
                        );


                        oAuth2Client.setCredentials({
                            refresh_token: '1//0425zDzPYkIwACgYIARAAGAQSNwF-L9IrcHizgrruMVzGNWpW6mSfrwxL3K-wGYqUv100uZ6O1WEAfKCH5eeNOVzbCGp1AttWdOo',
                        });

                        //Email Account To send otp to user email
                        const transporter = nodemailer.createTransport({
                            service: 'gmail',
                            auth: {
                                type: 'OAuth2',
                                user: 'jokerre90@gmail.com',
                                clientId: credentials.web.client_id,
                                clientSecret: credentials.web.client_secret,
                                refreshToken: '1//0425zDzPYkIwACgYIARAAGAQSNwF-L9IrcHizgrruMVzGNWpW6mSfrwxL3K-wGYqUv100uZ6O1WEAfKCH5eeNOVzbCGp1AttWdOo',
                                accessToken: oAuth2Client.getAccessToken(),
                            },
                        });

                        //Compose Email
                        const mailOptions = {
                            from: 'jokerre90@gmail.com',
                            to: email,
                            subject: 'Heath-I APP Account Recovery',
                            text: `Your OTP code is: ${otp}`,
                        };
                        //Send mail containing OTP to user email 
                        transporter.sendMail(mailOptions, (error, info) => {
                            if (error) {
                                console.error('Send mail error:', error);
                                socket.emit('otpInserted', { success: false, message: 'Sending mail error:', uid: 0, email: '', username: '', adminid: 0, facility: '' });
                            } else {
                                console.error('Mail sent to:', email);
                                socket.emit('otpInserted', { success: true, message: 'OTP sent successfully', uid: uid, email: email, username: username, adminid: adminid, facility: facility });
                            }
                        });

                    }
                });

            }
            else {
                console.log('User not found');
                socket.emit('otpInserted', { success: false, message: 'User not found', uid: 0, email: '', username: '', adminid: 0, facility: '' });
            }
        });
    });
    //OTP verification
    socket.on('otpVerification', async (data) => {
        const { uid, username, otp } = data;
    
        // For hashing OTP with Salt
        function hashOTP(otp, salt) {
            const hmac = crypto.createHmac('sha256', salt);
            const hashedOTP = hmac.update(otp).digest('hex');
            return hashedOTP;
        }
    
        try {
            const [results] = await db.execute('SELECT * FROM `user` WHERE `id` = ?  AND `username` = ?', [uid, username]);
    
            if (results.length > 0) {
                const storedOTPHash = results[0]['otp'];
                const storedSalt = results[0]['salt'];
    
                const hashedEnteredOTP = hashOTP(otp, storedSalt);
    
                if (hashedEnteredOTP === storedOTPHash) {
                    // OTP is correct
                    console.log('OTP authentication successful');
                    socket.emit('otpVerificationResponse', { success: true, message: 'OTP Authentication successful', uid });
                } else {
                    // OTP is incorrect
                    console.log('OTP authentication failed');
                    socket.emit('otpVerificationResponse', { success: false, message: 'OTP is incorrect!' });
                }
            } else {
                console.log('User not found');
                socket.emit('otpVerificationResponse', { success: false, message: 'User not found' });
            }
        } catch (error) {
            console.error('MySQL query error:', error);
    
            if (error.code === 'PROTOCOL_CONNECTION_LOST') {
                // Reconnect on connection lost
                try {
                    await db.connect();
                    console.log('Database reconnected');
                    // Retry the otpVerification after successful reconnection
                    socket.emit('otpVerification', data);
                } catch (reconnectError) {
                    console.error('Failed to reconnect to the database:', reconnectError);
                    socket.emit('otpVerificationResponse', { success: false, message: 'Failed to reconnect to the database' });
                }
            } else {
                socket.emit('otpVerificationResponse', { success: false, message: 'An unexpected error occurred' });
            }
        }
    });
    
    //Get Training Data for Algorithm
    socket.on('getTrainingData', async (data) => {
        const dataQuery = 'SELECT `gender`, `age`, `fhhypertension`, `fhstroke`, `fhheartdisease`, `fhdiabetes`, `fhasthma`, `fhcancer`, `fhkidneydisease`, `tabaccouse`, `alcoholintake`, `physicalactivity`, `nutrition`, `weight`, `height`, `bmi`, `waistcircumference`, `sbp`, `dbp`, `dhypertension`, `ddiabetes`, `tc`, `risk` FROM `records` WHERE 1';
    
        try {
            const [results] = await db.execute(dataQuery);
    
            socket.emit('retrieveTrainingData', results);
        } catch (error) {
            console.error('MySQL query error:', error);
    
            if (error.code === 'PROTOCOL_CONNECTION_LOST') {
                // Reconnect on connection lost
                try {
                    await db.connect();
                    console.log('Database reconnected');
                    // Retry the getTrainingData after successful reconnection
                    socket.emit('getTrainingData', data);
                } catch (reconnectError) {
                    console.error('Failed to reconnect to the database:', reconnectError);
                    //socket.emit('error', { message: 'Failed to reconnect to the database' });
                }
            } else {
                //socket.emit('error', { message: 'An unexpected error occurred' });
            }
        }
    });
    

    //Retrieve All Data From Table
    socket.on('query_db', async (uid) => {
        try {
            // Get the admin_id for the given user ID
            const userQuery = 'SELECT `admin_id` FROM `user` WHERE `id` = ?';
            const [userResults] = await db.execute(userQuery, [uid]);
    
            // Find all users under the specific admin
            const selectUsersQuery = 'SELECT id FROM user WHERE admin_id = ?';
            const [adminUsers] = await db.execute(selectUsersQuery, [userResults[0].admin_id]);
    
            // Extract user IDs from the results
            const userIDs = adminUsers.map(user => user.id);
    
            // Generate placeholders for the user IDs in the query
            const placeholders = userIDs.map(() => '?').join(',');
    
            // Select all records recorded by the identified users
            const selectRecordsQuery = `SELECT r.* FROM records r WHERE r.uid IN (${placeholders})`;
            const [recordsResults] = await db.execute(selectRecordsQuery, userIDs);
    
            // Send the query results to the client
            socket.emit('data_table', recordsResults);
        } catch (error) {
            console.error('MySQL query error:', error);
    
            if (error.code === 'PROTOCOL_CONNECTION_LOST') {
                // Reconnect on connection lost
                try {
                    await db.connect();
                    console.log('Database reconnected');
                    // Retry the query_db after successful reconnection
                    socket.emit('query_db', uid);
                } catch (reconnectError) {
                    console.error('Failed to reconnect to the database:', reconnectError);
                    //socket.emit('error', { message: 'Failed to reconnect to the database' });
                }
            } else {
                //socket.emit('error', { message: 'An unexpected error occurred' });
            }
        }
    });
    
    
    
    //Retrieve Specific Data as Record History
    socket.on('getrecordhistory', async (data) => {
        try {
            const { fname, mname, lname, suffix } = data;
    
            const query = 'SELECT * FROM `records` WHERE `fname` = ? AND `mname` = ? AND `lname` = ? AND `suffix` = ?';
            const [results] = await db.execute(query, [fname, mname, lname, suffix]);
    
            // Send the query results to the client
            socket.emit('retrieve_recordhistory', results);
        } catch (error) {
            console.error('MySQL query error:', error);
    
            if (error.code === 'PROTOCOL_CONNECTION_LOST') {
                // Reconnect on connection lost
                try {
                    await db.connect();
                    console.log('Database reconnected');
                    // Retry the getrecordhistory after successful reconnection
                    socket.emit('getrecordhistory', data);
                } catch (reconnectError) {
                    console.error('Failed to reconnect to the database:', reconnectError);
                    //socket.emit('error', { message: 'Failed to reconnect to the database' });
                }
            } else {
                //socket.emit('error', { message: 'An unexpected error occurred' });
            }
        }
    });
    
    //Retrieve Assessment history for result
    socket.on('get_assessment_history_data', async (userinfo) => {
        try {
            const { fname, mname, lname, gender } = userinfo;
    
            const query = 'SELECT * FROM `records` WHERE `fname` = ? AND `mname` = ? AND `lname` = ? AND `gender` = ?';
            const [results] = await db.execute(query, [fname, mname, lname, gender]);
    
            // Send the query results to the client
            socket.emit('recieve_assessment_history', results);
        } catch (error) {
            console.error('MySQL query error:', error);
    
            if (error.code === 'PROTOCOL_CONNECTION_LOST') {
                // Reconnect on connection lost
                try {
                    await db.connect();
                    console.log('Database reconnected');
                    // Retry the get_assessment_history_data after successful reconnection
                    socket.emit('get_assessment_history_data', userinfo);
                } catch (reconnectError) {
                    console.error('Failed to reconnect to the database:', reconnectError);
                    //socket.emit('error', { message: 'Failed to reconnect to the database' });
                }
            } else {
                //socket.emit('error', { message: 'An unexpected error occurred' });
            }
        }
    });






    
    //Chart Data Request for Dashboard
    socket.on('query_data', async (uid) => {
        try {
            const query = 'SELECT * FROM `records` WHERE `uid` = ?';
            const [results] = await db.execute(query, [uid]);
    
            // Send the query results to the client
            socket.emit('load_chart_data', results);
        } catch (error) {
            console.error('MySQL query error:', error);
    
            if (error.code === 'PROTOCOL_CONNECTION_LOST') {
                // Reconnect on connection lost
                try {
                    await db.connect();
                    console.log('Database reconnected');
                    // Retry the query_data after successful reconnection
                    socket.emit('query_data', uid);
                } catch (reconnectError) {
                    console.error('Failed to reconnect to the database:', reconnectError);
                    // Log the error to the console instead of emitting it
                    console.error('Failed to reconnect to the database');
                }
            } else {
                // Log the error to the console instead of emitting it
                console.error('An unexpected error occurred');
            }
        }
    });
    



    //Query Available Address On The Specific Facility
    socket.on('address_query', async (data) => {
        try {
            const { adminid } = data;
            const query = 'SELECT * FROM `address` WHERE `admin_id` = ?';
            const [results] = await db.execute(query, [adminid]);
    
            // Send the query results to the client
            socket.emit('addressData', results);
        } catch (error) {
            console.error('MySQL query error:', error);
    
            if (error.code === 'PROTOCOL_CONNECTION_LOST') {
                // Reconnect on connection lost
                try {
                    await db.connect();
                    console.log('Database reconnected');
                    // Retry the address_query after successful reconnection
                    socket.emit('address_query', data);
                } catch (reconnectError) {
                    console.error('Failed to reconnect to the database:', reconnectError);
                    // Log the error to the console instead of emitting it
                    console.error('Failed to reconnect to the database');
                }
            } else {
                // Log the error to the console instead of emitting it
                console.error('An unexpected error occurred');
            }
        }
    });
    

    //Insert Records To Record Management Table
    socket.on('insert_data', async (data) => {
        try {
            const insertquery = 'INSERT INTO `records`(`uid`, `dateassess`, `fname`, `mname`, `lname`, `suffix`, `gender`, `age`, `address`, `contact`, `fhhypertension`, `fhstroke`, `fhheartdisease`, `fhdiabetes`, `fhasthma`, `fhcancer`, `fhkidneydisease`, `tabaccouse`, `alcoholintake`, `physicalactivity`, `nutrition`, `weight`, `height`, `bmi`, `waistcircumference`, `sbp`, `dbp`, `dhypertension`, `ddiabetes`, `tc`, `risk`, predicted) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)';
    
            const values = [
                data.uid,
                data.dateassess,
                data.fname,
                data.mname,
                data.lname,
                data.suffix,
                data.gender,
                data.age,
                data.address,
                data.contact,
                data.fhhypertension,
                data.fhstroke,
                data.fhheartdisease,
                data.fhdiabetes,
                data.fhasthma,
                data.fhcancer,
                data.fhkidney,
                data.smoking,
                data.drinking,
                data.physical,
                data.dietary,
                data.weight,
                data.height,
                data.bmi,
                data.waist,
                data.systolic,
                data.diastolic,
                data.hypertension,
                data.presenceofdiabetes,
                data.tc,
                data.risk,
                data.predicted,
            ];
    
            const [results] = await db.execute(insertquery, values);
    
            // Query was successful
            console.log('Record inserted:', results);
            // Handle the success (e.g., send a success message to the client)
            console.log(data);
            socket.emit('insert_success');
        } catch (error) {
            console.error('MySQL query error:', error);
            // Handle the error (e.g., log it to console or send an error message to the client)
            // Log the error to the console instead of emitting it
            console.error('An unexpected error occurred');
        }
    });
    
    //Change User Profile Picture
    socket.on('uploadImage', async (data) => {
        try {
            const { userId, image } = data;
    
            // Update the user's image in the database
            const updateQuery = 'UPDATE `user` SET image = ? WHERE id = ?';
            const [results] = await db.execute(updateQuery, [image, userId]);
    
            if (results.affectedRows > 0) {
                // Image updated successfully
                console.log('Image updated successfully.');
    
                // Notify clients that the image was successfully updated
                socket.emit('changeprofilesuccess');
            } else {
                // No rows were affected, indicating that the user with the specified ID was not found
                console.log('User not found or image update failed.');
                // Handle the failure (e.g., emit an error message to the client)
                socket.emit('changeprofilefailure', { message: 'User not found or image update failed.' });
            }
        } catch (error) {
            console.error('MySQL query error:', error);
            // Handle the error (e.g., log it to console or send an error message to the client)
            // Log the error to the console instead of emitting it
            console.error('An unexpected error occurred');
        }
    });
    
    //Retrieving and Load New Profile Picture
    socket.on('retrieveImage', async (uid) => {
        try {
            // Retrieve the user's image from the database
            const selectQuery = 'SELECT `image` FROM `user` WHERE `id` = ?';
            const [results] = await db.execute(selectQuery, [uid]);
    
            if (results.length > 0) {
                // Retrieve the user's image and emit it to the client 
                socket.emit('imageRetrieved', { image: results[0].image });
            } else {
                // Handle when the image is not found
                console.log('Image not found for user with ID:', uid);
                // Emit an event to inform the client that the image is not found
                socket.emit('imageNotFound', { userId: uid });
            }
        } catch (error) {
            console.error('MySQL query error:', error);
            // Handle the error (e.g., log it to console or send an error message to the client)
            // Log the error to the console instead of emitting it
            console.error('An unexpected error occurred');
        }
    });
    
    //Update Password on OTP
    socket.on('changePassonOtp', async (data) => {
        try {
            const { uid, newpassword } = data;
    
            // For hashing password with Salt
            function hashPassword(password, salt) {
                const hmac = crypto.createHmac('sha256', salt);
                const hashedPassword = hmac.update(password).digest('hex');
                return hashedPassword;
            }
    
            const selectQuery = 'SELECT * FROM `user` WHERE `id` = ? AND `type` = "user"';
            const [userResults] = await db.execute(selectQuery, [uid]);
    
            if (userResults.length > 0) {
                const storedSalt = userResults[0]['salt'];
    
                const hashedNewPassword = hashPassword(newpassword, storedSalt);
    
                const updatePasswordQuery = 'UPDATE `user` SET `password_hash` = ? WHERE `id` = ?';
                await db.execute(updatePasswordQuery, [hashedNewPassword, uid]);
    
                const deleteOtpQuery = 'UPDATE `user` SET `otp` = NULL WHERE id = ?';
                await db.execute(deleteOtpQuery, [uid]);
    
                console.log('Password Updated!');
                socket.emit('onPasswordChanged');
            } else {
                // User not found
                console.log('User not found');
                socket.emit('errorDialog', { success: false, message: 'Unable to update username and password!' });
            }
        } catch (error) {
            console.error('MySQL query error:', error);
            // Handle the error (e.g., log it to console or send an error message to the client)
            // Log the error to the console instead of emitting it
            console.error('An unexpected error occurred');
            socket.emit('errorDialog', { success: false, message: 'An unexpected error occurred' });
        }
    });
    

    //Update Username & Password
    socket.on('updateUsernamePassword', async (data) => {
        try {
            const { uid, username, newpassword, enteredpassword } = data;
    
            // For hashing password with Salt
            function hashPassword(password, salt) {
                const hmac = crypto.createHmac('sha256', salt);
                const hashedPassword = hmac.update(password).digest('hex');
                return hashedPassword;
            }
    
            function generateSalt() {
                const crypto = require('crypto');
                const saltBytes = crypto.randomBytes(16);
                const salt = saltBytes.toString('base64');
                return salt;
            }
    
            const selectQuery = 'SELECT * FROM `user` WHERE `id` = ?';
            const [userResults] = await db.execute(selectQuery, [uid]);
    
            if (userResults.length > 0) {
                const storedPasswordHash = userResults[0]['password_hash'];
                const storedSalt = userResults[0]['salt'];
    
                const hashedEnteredPassword = hashPassword(enteredpassword, storedSalt);
    
                if (hashedEnteredPassword === storedPasswordHash || (hashedEnteredPassword === storedPasswordHash && newpassword.trim() === "")) {
                    // Password is correct
                    console.log('Authentication successful Changing Username or Password is now Permitted!');
    
                    // Update Only username
                    if (newpassword.trim() === "") {
                        const updateUsernameQuery = 'UPDATE `user` SET `username` = ? WHERE `id` = ?';
                        await db.execute(updateUsernameQuery, [username, uid]);
    
                        socket.emit('usernameUpdated', { 'username': username });
                        console.log('Only Username Updated!');
                    }
                    // Update both username and password
                    else {
                        const salt = generateSalt();
                        const hashedPassword = hashPassword(newpassword, salt);
    
                        const updateUsernamePasswordQuery = 'UPDATE `user` SET `username` = ?, `password_hash` = ?, `salt` = ? WHERE `id` = ?';
                        await db.execute(updateUsernamePasswordQuery, [username, hashedPassword, salt, uid]);
    
                        socket.emit('usernamePasswordUpdated', { 'username': username });
                        console.log('Username Password Updated!');
                    }
                } else {
                    // Password is incorrect
                    console.log('Authentication failed')
                    socket.emit('errorDialog', { success: false, message: 'Current Password is Incorrect!' });
                }
            } else {
                // User not found
                console.log('User not found');
                socket.emit('errorDialog', { success: false, message: 'Unable to update username and password!' });
            }
        } catch (error) {
            console.error('MySQL query error:', error);
            // Handle the error (e.g., log it to console or send an error message to the client)
            // Log the error to the console instead of emitting it
            console.error('An unexpected error occurred');
            socket.emit('errorDialog', { success: false, message: 'An unexpected error occurred' });
        }
    });
    
    //Load User Profile and user account information for App settings
    socket.on('loadProfile', async (uid) => {
        try {
            const [results] = await db.execute('SELECT * FROM `user` WHERE `id` = ?', [uid]);
    
            if (results.length > 0) {
                // Retrieve the user's data and emit it to the client
                socket.emit('onloadProfile', results[0]);
            } else {
                // Handle when the user is not found
                console.log('User not found');
                socket.emit('errorDialog', { success: false, message: 'User not found!' });
            }
        } catch (error) {
            console.error('MySQL query error:', error);
            // Handle the error (e.g., log it to console or send an error message to the client)
            // Log the error to the console instead of emitting it
            console.error('An unexpected error occurred');
            socket.emit('errorDialog', { success: false, message: 'An unexpected error occurred' });
        }
    });
    
    //Update Recovery Email
    socket.on('updateRecoveryEmail', async (data) => {
        const { uid, email } = data;
    
        try {
            await db.execute('UPDATE `user` SET `email` = ? WHERE `id` = ?', [email, uid]);
    
            // Retrieve email after updating and send it to the client
            socket.emit('emailhasUpdated', { 'email': email });
        } catch (error) {
            console.error('MySQL query error:', error);
            // Handle the error (e.g., log it to console or send an error message to the client)
            // Log the error to the console instead of emitting it
            console.error('An unexpected error occurred');
            socket.emit('errorDialog', { success: false, message: 'An unexpected error occurred' });
        }
    });
    
    // Delete Rocords From the Record Management Table
    socket.on('delete_record', async (data) => {
        const { id, fname, mname, lname, suffix } = data;
    
        try {
            // Delete the record with the specified id
            await db.execute('DELETE FROM `records` WHERE id = ?', [id]);
    
            // Retrieve updated record history after deletion
            const query = 'SELECT * FROM `records` WHERE `fname` = ? AND `mname` = ? AND `lname` = ? AND `suffix` = ?';
            const records = await db.query(query, [fname, mname, lname, suffix]);
    
            // Send the updated record history to the client
            socket.emit('retrieve_recordhistory', records);
        } catch (error) {
            console.error('MySQL query error:', error);
            // Handle the error (e.g., log it to the console or send an error message to the client)
            // Log the error to the console instead of emitting it
            console.error('An unexpected error occurred');
            socket.emit('errorDialog', { success: false, message: 'An unexpected error occurred' });
        }
    });    

    // Update user Bio
    socket.on('updateBio', async (data) => {
        const { uid, fname, mname, lname, affiliation } = data;
    
        try {
            // Update user bio information in the database
            const updateQuery = 'UPDATE `user` SET `fname` = ?, `mname` = ?, `lname` = ?, `affiliation` = ? WHERE `id` = ?';
            await db.execute(updateQuery, [fname, mname, lname, affiliation, uid]);
    
            // Emit the updated bio information to the client
            socket.emit('onbioUpdated', { 'fname': fname, 'mname': mname, 'lname': lname, 'affiliation': affiliation });
        } catch (error) {
            console.error('MySQL query error:', error);
            // Handle the error (e.g., log it to the console or send an error message to the client)
            // Log the error to the console instead of emitting it
            console.error('An unexpected error occurred');
            socket.emit('errorDialog', { success: false, message: 'An unexpected error occurred' });
        }
    });
    

    socket.on('disconnect', async () => {
        console.log('A user disconnected');
    });
});

const port = process.env.PORT || 3001; // Set the port number you want to use
server.listen(port, async () => {
    console.log(`Socket.IO Server is running on port ${port}`);
});





