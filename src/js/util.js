// Casts a rejected promise to an error rather than a
// simple string result
const throwErrorOnRejectedPromise = async (promise, errorMessage) => {
    try {
        return await promise;
    } catch (ex) {
        if (errorMessage) {
            throw new Error(errorMessage);
        }
        throw new Error(ex);
    }
};

module.exports = {
    throwErrorOnRejectedPromise
}