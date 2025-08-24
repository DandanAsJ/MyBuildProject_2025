// require('dotenv').config();

// module.exports = {
//   "development": {
//     "url": process.env.DATABASE_URL,
//     "dialect": 'postgres',
//     dialectOptions: {
//       ssl: process.env.DB_SSL === 'true' ? {  // 改为动态控制
//         require: true,
//         rejectUnauthorized: false
//       } : false
//     },
//     protocol: 'postgres',  // 明确指定协议
//     logging: console.log   // 启用查询日志
//   },

//   "test": {
//     "url": process.env.DATABASE_URL,
//     "dialect": 'postgres'
//   },
//   "production": {
//     "url": process.env.DATABASE_URL,
//     "dialect": 'postgres',
//     "dialectOptions": {
//       "ssl": {
//         "require": true,
//         "rejectUnauthorized": false
//       }
//     }
//   }
// };



require('dotenv').config();
const { URL } = require('url');

// 解析连接字符串
const dbUrl = new URL(process.env.DATABASE_URL);

// 提取连接参数
const config = {
  username: dbUrl.username,
  password: dbUrl.password,
  host: dbUrl.hostname,
  port: dbUrl.port,
  database: dbUrl.pathname.substring(1),
  dialect: 'postgres',
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: false
    }
  },
  //logging: console.log // 启用查询日志
};

// 测试连接（可选）
// const { Sequelize } = require('sequelize');
// const testSequelize = new Sequelize(config);
// testSequelize.authenticate()
//   .then(() => console.log('Sequelize 连接测试成功'))
//   .catch(err => console.error('Sequelize 连接测试失败:', err));

module.exports = {
  development: config,
  test: config,
  production: config
};