// Test file containing intentional security issues for scanner validation
const express = require('express');
const app = express();

// 1. Hardcoded Secrets (AWS & generic API token)
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const slackWebhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";
const dbPassword = "mysql://admin:SuperSecretPassword123@192.168.1.50:3306/prod_db";

// 2. Loose CORS wildcard policy
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  next();
});

// 3. Command Injection and Insecure Hashing
const { exec } = require('child_process');
const crypto = require('crypto');

app.get('/ping', (req, res) => {
  const host = req.query.host;
  
  // Vulnerable to Command Injection
  exec("ping -c 1 " + host, (err, stdout, stderr) => {
    res.send(stdout);
  });
});

app.get('/login', (req, res) => {
  const password = req.query.password;
  
  // Insecure Hashing algorithm MD5
  const hash = crypto.createHash('md5').update(password).digest('hex');
  
  // Sensitive logging of credentials
  console.log("User password hash: " + hash + " for password: " + password);
  
  // Vulnerable eval execution
  const dynamicCode = `console.log("Logging user: " + "${req.query.username}")`;
  eval(dynamicCode);

  res.send("Logged in!");
});

app.listen(8080, () => {
  console.log("Server listening on port 8080");
});
