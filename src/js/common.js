function ensurePositiveInteger(num) {
    if (!Number.isInteger(num) || num < 0) {
        throw new Error(`Need a positive integer but found ${num} `);
    }
}

module.exports = {
    ensurePositiveInteger
}