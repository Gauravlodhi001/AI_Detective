const db = require('./db');

exports.queryUser = async (req, res) => {
  const userId = req.query.id;
  const sql = "SELECT * FROM users WHERE id = " + userId;
  const data = await db.query(sql);
  res.json(data);
};
