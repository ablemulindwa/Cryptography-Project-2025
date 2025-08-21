//My Subtle Crypto imports
import {webcrypto} from 'crypto';
const subtle = webcrypto.subtle;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters
const SALT_LENGTH = 16;

//Two variables, for use with the getKeys() function.
// Master password. A sample. Might need to prompt the user in the final implementation.
const master_password = "myultimatemasterpassword";
// Generate a salt. Might need to store it later.
const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));

//My working Key Value Store. Initializes a default key value store to be used to run experiments on.
//Domain names
let domain_name = ["mozilla.org", "strathmore.edu", "amazon.com", "google.com", "walmart.com"];

//Passwords
let password = ["password1","password2","password3","password4","password5"];

//Using a map
let mp = new Map();

//Populate the map.
for(let i = 0; i < domain_name.length; i++){
    mp.set(domain_name[i],password[i]);
}

//Junk variables. To test updating system.
let key1 = "example.com";
let value1 = "password6";
let value2 = "password10";

//My variable to check if the key in KVS exists. Required for check() functionality.
let bool = true;

//mp.set(key1,value2);

//DONE: Function to derive keys for both encryption and decryption.
async function getKeys(password, salt, iterations){
    //Encode the master password given by user.
    const encodedMasterPassword = new TextEncoder().encode(password);
    
    //Import the password into a Cryptokey
    const masterKey = await crypto.subtle.importKey(
        'raw',
        encodedMasterPassword,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    //Derive the master key k using the Cryptokey
    const k = await crypto.subtle.deriveKey(
    {
        name: "PBKDF2",
        salt: salt,
        iterations: iterations,
        hash: "SHA-256",
    },
        masterKey,
        { name: "HMAC", hash: "SHA-256" },
        true,
        ["sign", "verify"]
    );

    //Get two subkeys from master key k. To MAC the domain names in the KVS. As well as encrypt the password.
    //Derive HMAC sub-key for Domain MAC.
    const hmacKeyMaterial = await subtle.sign(
        "HMAC",
        k,
        new TextEncoder().encode("MY_HMAC_KEY")
    );

    const hmacKey = await subtle.importKey(
        "raw",
        hmacKeyMaterial,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"]
    );

    //Derive AES sub-key for eventual AES-GCM encryption
    const aesKeyMaterial = await subtle.sign(
        "HMAC",
        k,
        new TextEncoder().encode("MY_AES_KEY")
    );

    // Ensure that AES-GCM is exactly 256 bits
    const aesKeyM = new Uint8Array(aesKeyMaterial).slice(0, 32);
    const aesKey = await subtle.importKey(
        "raw",
        aesKeyM,
        "AES-GCM",
        false,
        ["encrypt", "decrypt"]
    );

    //Return the keys to be used for encryption/decryption
    return { hmacKey, aesKey };
}

//TO-DO: Combine the set function below with the get Keys function above it. Maybe find a way to save the keys as well?
async function set(key, value){

    //Does the given key exist?
    if(check(key) != true) {
        //No? Add a new record into the system.
        //TO-DO: Step 1: Hash the domain name
        
        //Step 2: Encrypt password and insert new record into the system.
        let encrypted_password = await pass_encrypt(value);
        //console.log(encrypted_password);
        
        mp.set(key, encrypted_password);
        //console.log(mp.entries());
        //console.log("Just inserted a new record!!");
    } else {
        
        //Yes? Update the password's content.
        update(key,value);
    }

}

// Test if the new entry was added.
await set(key1, value1);
console.log(mp.entries());

//TO-DO: Check. An outside function that checks whether a key value exists in the KVS. Returns true or false if value exists.
function check(key){
    //TO-DO: Before or during each iteration of the (by this point), encrypted domain names,
    //find a way in order to decrypt that domain name first. Might need to be done on an individual basis, but don't forget.

    //Iterates over each value in order to find if key(domain name) exists in KVS.
    for(const yek of mp.keys()){
        
        //Prints keys. For testing.
        //console.log("The Keys are: " + yek);
        
        //If key doesn't exist. Proceed to adding new key.
        if(yek != key){
            bool = false;        
        }
        //If key exists. Stop and think. Might need to update the old password
        else {    
            bool = true;
            break;
        }
    }

    return bool;
}

//DONE: Update. An outside function that updates the password/value in the key-value pair if a match is found with the domain.
//TO-DO: Consider adding a dependency to the centralized getKeys() function in order to facilitate better, more secure and accurate updating.
function update(key, value){
    //Iterates over each value.
    for(const yek of mp.keys()){
        //If key is present, but password doesn't match.
        if(key == yek && value != mp.get(yek)){
            //console.log("Most relevant Record");
            //Replace the password there with the new password.
            mp.set(key,value);
            //console.log("Record successfully changed");
        } else {
            //console.log("Irrelevant Record.");
        }
    }
}

//TO-DO: Encrypt. An outside function that encrypts the value of the password. Combine this function with the getKeys() function.
async function pass_encrypt(value){
    //Preparing the Data
    const pass_encoded = new TextEncoder().encode(value);

    //Encryption Key, very important for encryption and decryption
    const encrypt_key = await crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256,
        }, 
        true, 
        ["encrypt","decrypt"],
    );

    //Initialization Vector, required for the encryption
    const iv = crypto.getRandomValues(new Uint8Array(12));

    //Actual Encryption function
    const pass_cipher = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        encrypt_key,
        pass_encoded
    );

    //Test if encryption is done successfully.
    //console.log(pass_cipher);

    return pass_cipher;
}

//TO-DO: Domain Hash. An outside function dedicated specifically to getting the HMAC of the domain value
