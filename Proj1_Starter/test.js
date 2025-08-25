"use strict";

const { Keychain } = require("./password-manager.js");
const { webcrypto } = require('crypto');
const { subtle } = webcrypto;
const assert = require('assert');


async function runTests() {
    console.log("--- Running Keychain Tests ---");
    const masterPassword = "my-super-secret-password-123";
    const wrongPassword = "my-wrong-password";

    // Test 1: Initialization
    console.log("\n[Test 1] Keychain.init()");
    let keychain = await Keychain.init(masterPassword);
    assert.ok(keychain instanceof Keychain, "init() should return a Keychain instance");
    assert.equal(Object.keys(keychain.data.kvs).length, 0, "New keychain should be empty");
    console.log("PASSED");

    // Test 2: Set and Get
    console.log("\n[Test 2] set() and get()");
    const domain1 = "example.com";
    const pass1 = "p@ssword1";
    await keychain.set(domain1, pass1);
    const retrievedPass1 = await keychain.get(domain1);
    assert.strictEqual(retrievedPass1, pass1, "Should retrieve the correct password");
    console.log("PASSED");

    // Test 3: Get non-existent
    console.log("\n[Test 3] get() non-existent domain");
    const nonExistent = await keychain.get("nonexistent.com");
    assert.strictEqual(nonExistent, null, "Should return null for non-existent domain");
    console.log("PASSED");

    // Test 4: Update existing entry
    console.log("\n[Test 4] set() to update an existing entry");
    const pass1Updated = "new-p@ssword1";
    await keychain.set(domain1, pass1Updated);
    const retrievedUpdatedPass1 = await keychain.get(domain1);
    assert.strictEqual(retrievedUpdatedPass1, pass1Updated, "Should retrieve the updated password");
    console.log("PASSED");

    // Test 5: Remove entry
    console.log("\n[Test 5] remove()");
    const removeResult = await keychain.remove(domain1);
    assert.strictEqual(removeResult, true, "remove() should return true for existing item");
    const getAfterRemove = await keychain.get(domain1);
    assert.strictEqual(getAfterRemove, null, "get() should return null after remove()");
    const removeNonExistent = await keychain.remove("nonexistent.com");
    assert.strictEqual(removeNonExistent, false, "remove() should return false for non-existent item");
    console.log("PASSED");

    // Test 6: Dump and Load
    console.log("\n[Test 6] dump() and load()");
    await keychain.set("google.com", "google-pass");
    await keychain.set("github.com", "github-pass");
    const [dumpedData, checksum] = await keychain.dump();

    const loadedKeychain = await Keychain.load(masterPassword, dumpedData, checksum);
    assert.ok(loadedKeychain instanceof Keychain, "load() should return a Keychain instance");

    const googlePass = await loadedKeychain.get("google.com");
    assert.strictEqual(googlePass, "google-pass", "Loaded keychain should have correct data");
    const githubPass = await loadedKeychain.get("github.com");
    assert.strictEqual(githubPass, "github-pass", "Loaded keychain should have correct data");
    console.log("PASSED");

    // Test 7: Load with wrong password
    console.log("\n[Test 7] load() with wrong password");
    const loadedWithWrongPass = await Keychain.load(wrongPassword, dumpedData, checksum);
    const getWithWrongPass = await loadedWithWrongPass.get("google.com");
    assert.strictEqual(getWithWrongPass, null, "get() should fail and return null with wrong password");
    console.log("PASSED");

    // Test 8: Load with bad checksum
    console.log("\n[Test 8] load() with bad checksum");
    await assert.rejects(
        Keychain.load(masterPassword, dumpedData, "badchecksum-in-base64-format-that-is-wrong"),
        { message: "Integrity check failed - data may have been tampered with" },
        "Should reject promise for bad checksum"
    );
    console.log("PASSED");

    // Test 9: Swap Attack Protection (AAD)
    console.log("\n[Test 9] Swap Attack Protection");
    const [dumpedDataForSwap] = await keychain.dump();
    const parsedForSwap = JSON.parse(dumpedDataForSwap);

    // Manually find the hashed domains for google.com and github.com
    const hashedGoogle = await keychain._hashDomain("google.com");
    const hashedGithub = await keychain._hashDomain("github.com");

    // Swap the encrypted passwords
    const temp = parsedForSwap.kvs[hashedGoogle];
    parsedForSwap.kvs[hashedGoogle] = parsedForSwap.kvs[hashedGithub];
    parsedForSwap.kvs[hashedGithub] = temp;

    const tamperedData = JSON.stringify(parsedForSwap);

    // We load without the checksum for this specific test to isolate the AAD failure
    const tamperedKeychain = await Keychain.load(masterPassword, tamperedData, false);

    // Attempting to get google.com's password should now fail because it's encrypted with github.com as AAD
    const getTampered = await tamperedKeychain.get("google.com");
    assert.strictEqual(getTampered, null, "get() should fail decryption and return null for swapped password");
    console.log("PASSED");

    console.log("\n--- All Tests Passed Successfully! ---");
}

runTests().catch(err => {
    console.error("\n A TEST FAILED:", err);
    process.exit(1);
});
