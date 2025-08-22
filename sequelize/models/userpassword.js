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
        password: { type: DataTypes.TEXT, allowNull: false }, // will be encrypted
        sharedByUserId: DataTypes.INTEGER,
        weak_encryption: DataTypes.BOOLEAN,
        source_password_id: DataTypes.INTEGER
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
