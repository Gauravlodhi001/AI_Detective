const service = require('./cross_file_service');

exports.run = (req, res) => {
  const command = req.body.cmd;
  service.executeCommand(command, res);
};
