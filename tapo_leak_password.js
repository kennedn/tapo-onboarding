Java.perform(function () {
    let Account = Java.use("com.tplink.libtapocameranetwork.model.Account");
    Account.getPassword.implementation = function () {
        let username = this.username.value
        let password = this.password.value
        console.log(`[Account.getPassword()] -> username=${username}, password=${password}`);
        return password;
    };
});

