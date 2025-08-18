module.exports = (sequelize, DataTypes) => {
    const UserPassword = sequelize.define('UserPassword', {
        ownerUserId: { //the corresponding user id in users table
            type: DataTypes.INTEGER,
            allowNull: false,
        },
        url: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        label: { type: DataTypes.STRING },
        username: { type: DataTypes.TEXT, allowNull: false },
        password: { type: DataTypes.TEXT, allowNull: false } // 存加密后的字符串
    }, {
        tableName: 'passwords',
        timestamps: true,
        underscored: false
    });

    UserPassword.associate = (models) => {
        UserPassword.belongsTo(models.User, { foreignKey: 'ownerUserId', as: 'owner' });
    };

    return UserPassword;
};
