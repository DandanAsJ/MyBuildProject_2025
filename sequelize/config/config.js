
module.exports = {
  "development": {
    "url": "postgresql://dandan:zky68T3IFGlJk34O6yU4Ts911oRhU5um@dpg-d1vsqg7diees73c0q570-a.oregon-postgres.render.com/firstdb_p58o?sslmode=require",
    "dialect": 'postgres',
    dialectOptions: {
      ssl: {
        require: true,
        rejectUnauthorized: false
      }
    }

  },
  "test": {
    "url": process.env.DATABASE_URL,
    "dialect": 'postgres'
  },
  "production": {
    "url": process.env.DATABASE_URL,
    "dialect": 'postgres',
    "dialectOptions": {
      "ssl": {
        "require": true,
        "rejectUnauthorized": false
      }
    }
  }
};