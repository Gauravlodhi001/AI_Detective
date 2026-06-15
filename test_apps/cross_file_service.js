const cp = require('child_process');

exports.executeCommand = (cmdStr, res) => {
  cp.exec(cmdStr, (err, out) => {
    res.send(out);
  });
};
