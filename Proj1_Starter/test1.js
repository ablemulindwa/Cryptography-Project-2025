//My Subtle Crypto imports
import {webcrypto} from 'crypto';
const subtle = webcrypto.subtle;

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

async function set(key, value){

    //Does the given key exist?
    if(check(key) != true) {
        //No? Add a new record into the system.
        //TO-DO: Step 1: Hash the domain name
        
        //Step 2: Encrypt password and insert new record into the system.
        let encrypted_password = await p_encrypt(value);
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

//TO-DO: Encrypt. An outside(?) function that encrypts the value of the password.
async function p_encrypt(value){
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