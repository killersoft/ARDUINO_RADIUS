#include <Arduino.h>
#include "DES.h"
#include "MD5.h"
#include "MD4.h"
#include "SHA1.h"
#include <string.h>

// Create instances of the cryptographic classes
DES des;
MD5 md5;
MD4 md4;
extern Sha1Class Sha1;

// Function to print an array in uppercase HEX without spaces
void printArray(uint8_t* array, size_t size) {
  for (size_t i = 0; i < size; i++) {
    if (array[i] < 0x10) {
      Serial.print("0");
    }
    Serial.print(array[i], HEX);
  }
  Serial.println();
}

// Function to convert a lowercase hex string to uppercase
void printUppercaseHex(const char* str) {
  while (*str) {
    char c = *str;
    if (c >= 'a' && c <= 'f') {
      c = c - 'a' + 'A';
    }
    Serial.print(c);
    str++;
  }
  Serial.println();
}

// Function to test DES encryption and decryption
void testDES() {
  byte out[8];
  byte in[] =  { 1, 2, 3, 4, 5, 6, 0x3B, 254 };
  byte key[] = { 0x3B, 0x38, 0x98, 0x37, 0x15, 0x20, 0xF7, 0x5E };

  Serial.println("========= DES test ==========");
  Serial.print("Data: ");
  printArray(in, 8); // Print input data
  Serial.print("Key: ");
  printArray(key, 8); // Print key

  // Encrypt
  Serial.print("Encrypt...");
  unsigned long timeStart = micros();
  des.encrypt(out, in, key); // Perform encryption
  unsigned long timeEnd = micros();
  unsigned long duration = timeEnd - timeStart;
  Serial.print("done. (");
  Serial.print(duration);
  Serial.print(" µs / ");
  Serial.print(duration / 1000.0);
  Serial.println(" ms)");
  Serial.print("Encrypted data: ");
  printArray(out, 8); // Print encrypted data

  // Decrypt
  for (int i = 0; i < 8; i++) {
    in[i] = out[i];
  }
  Serial.print("Decrypt...");
  timeStart = micros();
  des.decrypt(out, in, key); // Perform decryption
  timeEnd = micros();
  duration = timeEnd - timeStart;
  Serial.print("done. (");
  Serial.print(duration);
  Serial.print(" µs / ");
  Serial.print(duration / 1000.0);
  Serial.println(" ms)");
  Serial.print("Decrypted data: ");
  printArray(out, 8); // Print decrypted data
}

// Function to test MD5 hashing and HMAC-MD5
void testMD5() {
  const char *data = "The quick brown fox jumps over the lazy dog";
  const char *expectedHash = "9E107D9D372BB6826BD81D3542A419D6";
  
  Serial.println("========= MD5 test ==========");
  Serial.print("Data: ");
  Serial.println(data); // Print input data
  Serial.print("Expected MD5 Hash: ");
  Serial.println(expectedHash); // Print expected MD5 hash

  unsigned long timeStart = micros();
  unsigned char* md5Hash = md5.make_hash((const void *)data); // Compute MD5 hash
  unsigned long timeEnd = micros();
  unsigned long duration = timeEnd - timeStart;

  Serial.print("Actual MD5 Hash: ");
  for (int i = 0; i < 16; i++) {
    if (md5Hash[i] < 0x10) Serial.print("0");
    Serial.print(md5Hash[i], HEX);
  }
  Serial.println();
  Serial.print("Time taken: ");
  Serial.print(duration);
  Serial.print(" µs / ");
  Serial.print(duration / 1000.0);
  Serial.println(" ms");

  const char *key = "key";
  const char *expectedHmacHash = "80070713463E7749B90C2DC24911E275";
  Serial.print("HMAC Key: ");
  Serial.println(key); // Print HMAC key
  Serial.print("Expected HMAC-MD5: ");
  Serial.println(expectedHmacHash); // Print expected HMAC-MD5

  timeStart = micros();
  char* hmacHash = md5.hmac_md5(data, strlen(data), (void *)key, strlen(key)); // Compute HMAC-MD5
  timeEnd = micros();
  duration = timeEnd - timeStart;

  Serial.print("Actual HMAC-MD5: ");
  printUppercaseHex(hmacHash); // Print actual HMAC-MD5 in uppercase
  Serial.print("Time taken: ");
  Serial.print(duration);
  Serial.print(" µs / ");
  Serial.print(duration / 1000.0);
  Serial.println(" ms");

  free(md5Hash);  // Free the allocated memory for MD5 hash
  free(hmacHash); // Free the allocated memory for HMAC-MD5
}

// Function to test MD4 hashing
void testMD4() {
  const char *data = "Hello, world!";
  const char *expectedHash = "ABE9EE1F376CAA1BCECAD9042F16E73";

  Serial.println("========= MD4 test ==========");
  Serial.print("Data: ");
  Serial.println(data); // Print input data
  Serial.print("Expected MD4 Hash: ");
  Serial.println(expectedHash); // Print expected MD4 hash

  uint8_t hash[16];

  unsigned long timeStart = micros();
  md4.reset();
  md4.update((const uint8_t *)data, strlen(data)); // Update MD4 with data
  md4.finalize(hash); // Finalize MD4 hash
  unsigned long timeEnd = micros();
  unsigned long duration = timeEnd - timeStart;

  Serial.print("Actual MD4 Hash: ");
  for (int i = 0; i < 16; i++) {
    if (hash[i] < 0x10) Serial.print("0");
    Serial.print(hash[i], HEX);
  }
  Serial.println();
  Serial.print("Time taken: ");
  Serial.print(duration);
  Serial.print(" µs / ");
  Serial.print(duration / 1000.0);
  Serial.println(" ms");
}

// Function to test SHA1 hashing
void testSHA1() {
  const char *data = "The quick brown fox jumps over the lazy dog";
  const char *expectedHash = "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12";

  Serial.println("========= SHA1 test ==========");
  Serial.print("Data: ");
  Serial.println(data); // Print input data
  Serial.print("Expected SHA1 Hash: ");
  Serial.println(expectedHash); // Print expected SHA1 hash

  uint8_t hash[20]; // SHA1 produces a 20-byte hash

  unsigned long timeStart = micros();
  Sha1.init(); // Initialize SHA1
  Sha1.write((const uint8_t*)data, strlen(data)); // Update SHA1 with data
  memcpy(hash, Sha1.result(), 20); // Finalize SHA1 hash
  unsigned long timeEnd = micros();
  unsigned long duration = timeEnd - timeStart;

  Serial.print("Actual SHA1 Hash: ");
  for (int i = 0; i < 20; i++) {
    if (hash[i] < 0x10) Serial.print("0");
    Serial.print(hash[i], HEX);
  }
  Serial.println();
  Serial.print("Time taken: ");
  Serial.print(duration);
  Serial.print(" µs / ");
  Serial.print(duration / 1000.0);
  Serial.println(" ms");
}

// Arduino setup function
void setup() {
  Serial.begin(9600); // Initialize serial communication
  delay(5000); // Wait for serial monitor to open
  testDES();
  testMD5();
  testMD4();
  testSHA1();
}

// Arduino loop function (not used in this example)
void loop() {
  // Nothing to do here
}
