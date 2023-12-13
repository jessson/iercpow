const ethers = require('ethers')
const fs = require('fs')

const pkeys = []
for (let i = 0; i < 10; ++i) {
    var privateKey = ethers.utils.randomBytes(32);
    var wallet = new ethers.Wallet(privateKey);
    const pkey = Buffer.from(privateKey).toString('hex')
    console.log("账号地址: " + wallet.address);
    pkeys.push(pkey)
}
console.log(pkeys)
fs.writeFileSync("./src/pkey.json", JSON.stringify(pkeys, null, 2))