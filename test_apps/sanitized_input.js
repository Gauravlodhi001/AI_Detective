const cp = require('child_process');
const validator = require('validator');

exports.run = (req, res) => {
  const cmd = req.body.cmd;
  const safeCmd = validator.escape(cmd);
  cp.exec(safeCmd, (err, out) => {
    res.send(out);
  });
};
