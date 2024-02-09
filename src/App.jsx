import { useEffect, useState } from 'react'
import CryptoJS from 'crypto-js';
import { FaArrowUp } from "react-icons/fa";
import { FaGithub } from "react-icons/fa";

import './App.css'

const algorithmsDescriptions = {
  aes: `AES (Advanced Encryption Standard) is a secure encryption method that uses a key to encrypt and decrypt data.
  It operates on 128-bit blocks and accepts keys of 128, 192, or 256 bits. It's symmetric and widely used for securing data in networks, 
  storage, and communications. It requires a secret key to operate.`,
  md5: `MD5 (Message Digest Algorithm 5) is a widely used cryptographic hash function that produces a 128-bit hash value. 
  It's commonly used for verifying data integrity, generating digital signatures, and storing passwords securely. MD5 is one-way, 
  meaning it cannot be reversed to obtain the original input. However, it's considered vulnerable to collision attacks, 
  making it less secure for cryptographic purposes in modern applications.`,
  sha1: `SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function that generates a 160-bit hash value. 
  It's commonly used for data integrity verification, digital signatures, and certificate authorities. However, 
  it's considered less secure than newer hash functions due to vulnerabilities discovered over time, including collision attacks. 
  As a result, it's being deprecated in favor of more secure hash algorithms such as SHA-256 and SHA-3.`,
  sha2: `SHA-2 (Secure Hash Algorithm 2) is a family of cryptographic hash functions, including SHA-224, SHA-256, SHA-384, SHA-512, 
  SHA-512/224, and SHA-512/256. These algorithms produce hash values ranging from 224 to 512 bits in length. SHA-2 is widely used for 
  data integrity verification, digital signatures, and certificate authorities due to its strong security properties. It's considered 
  more secure than SHA-1 and is commonly used in modern cryptographic applications.`,
  sha3: `SHA-3 (Secure Hash Algorithm 3) is a cryptographic hash function standardized by NIST in 2015. 
  It's designed to provide improved security and performance compared to previous hash functions like SHA-1 and SHA-2. 
  SHA-3 operates on various input lengths, producing hash values of different lengths, including SHA3-224, SHA3-256, SHA3-384, 
  and SHA3-512. It's resistant to many cryptographic attacks and is suitable for data integrity verification, digital signatures, 
  and other cryptographic applications.`,
  ripemd160: `RIPEMD-160 (RACE Integrity Primitives Evaluation Message Digest 160) is a cryptographic hash function that produces a 
  fixed-size 160-bit hash value. It's commonly used in cryptocurrency applications, particularly in Bitcoin, for creating addresses 
  from public keys. RIPEMD-160 is designed to be resistant to differential cryptanalysis and has a simpler structure compared to some 
  other hash functions. However, it's not as widely used as SHA-2 or SHA-3 in mainstream cryptographic applications.`,
  hmacSha256: `It's a widely used cryptographic algorithm for generating a keyed hash message authentication code (HMAC) 
  using the SHA-256 hash function. HMAC-SHA256 provides integrity and authenticity assurances for data and is commonly 
  used in various security protocols such as TLS, IPsec, and OAuth. It's considered secure and resistant to known cryptographic 
  attacks when implemented correctly.`,
  pbkdf2: `PBKDF2 (Password-Based Key Derivation Function 2) is a key derivation function that's widely used for securely deriving 
  cryptographic keys from passwords or passphrase-based inputs. It applies a pseudorandom function (usually a cryptographic hash function 
  like HMAC-SHA1, HMAC-SHA256, etc.) iteratively to the input along with a salt value to produce a derived key. PBKDF2 offers 
  configurable parameters such as the number of iterations to increase the computational cost, enhancing security against brute-force 
  attacks. It's commonly used for password hashing and key stretching in security protocols and applications.`,
  des: `DES (Data Encryption Standard) is a symmetric-key block cipher algorithm that operates on 64-bit blocks of data using a 
  56-bit key. It employs a Feistel network structure, consisting of 16 rounds of encryption. Despite being widely used in the past, 
  DES is now considered insecure due to its small key size, making it vulnerable to brute-force attacks. It's been largely replaced 
  by more secure algorithms like AES.`,
  rabbit: `Rabbit is a stream cipher algorithm designed for high speed and security. 
  It's notable for its efficient performance in both hardware and software implementations. 
  Rabbit operates on 128-bit blocks of data and uses a 128-bit key. It generates a keystream by combining both nonlinear 
  feedback shift registers (NLFSRs) and linear feedback shift registers (LFSRs). Rabbit offers strong cryptographic security 
  and is suitable for various applications requiring efficient encryption, such as secure communications and storage systems.`
}

const HistoryItem = ({ algorithm, inputLog, method, handleClick }) => {
  return (
    <div className='history-item' onClick={handleClick}>
      <div className='history-item-header'>
        <p>{algorithm}</p>
        <p>{method}</p>
      </div>
      <p className='history-item-body'>{inputLog.mainInput}</p>
    </div>
  )
}

function App() {
  const [darkMode, setDarkMode] = useState(true)

  const [encryptMode, setEncryptMode] = useState(true)
  const [algorithm, setAlgorithm] = useState("aes")

  const [originalString, setOriginalString] = useState('');
  const [encryptedString, setEncryptedString] = useState('');

  const [originalHash, setOriginalHash] = useState("");
  const [decryptedHash, setDecryptedHash] = useState("");
  const [generatedSalt, setGeneratedSalt] = useState("")

  const [key, setKey] = useState("myKey")
  const [password, setPassword] = useState("mySecretPassword")
  const [salt, setSalt] = useState("mySalt")
  const [iterations, setIterations] = useState(10000)
  const [iv, setIv] = useState("myInitialValue")

  const [history, setHistory] = useState([])




  const handleOpenGitHub = () => {
    window.open("https://github.com/eliasitom/text-cipher", "_blank")
  }


  const e_AES = () => {
    if (!key) return alert("You need to add a key");

    // Encriptar 
    const encrypted = CryptoJS.AES.encrypt(originalString, key).toString()
    setEncryptedString(encrypted)
  };
  const d_AES = () => {
    if (!key) return alert("You need to add a key");

    const bytes = CryptoJS.AES.decrypt(originalHash, key)
    setDecryptedHash(bytes.toString(CryptoJS.enc.Utf8))
  }

  const e_MD5 = () => {
    const encrypted = CryptoJS.MD5(originalString)
    setEncryptedString(encrypted.toString())

    // Algoritmo unidireccional (no se puede desencriptar)
  }
  const e_SHA1 = () => {
    const hash = CryptoJS.SHA1(originalString)
    const hexHash = hash.toString(CryptoJS.enc.Hex)
    setEncryptedString(hexHash);

    // Algoritmo unidireccional (no se puede desencriptar)
  }
  const e_SHA2 = () => {
    const hash = CryptoJS.SHA256(originalString)
    const hexHash = hash.toString(CryptoJS.enc.Hex)
    setEncryptedString(hexHash);

    // Algoritmo unidireccional (no se puede desencriptar)
  }
  const e_SHA3 = () => {
    const hash = CryptoJS.SHA3(originalString)
    const hexHash = hash.toString(CryptoJS.enc.Hex)
    setEncryptedString(hexHash);

    // Algoritmo unidireccional (no se puede desencriptar)
  }
  const e_RIPEMD160 = () => {
    const hash = CryptoJS.RIPEMD160(originalString)
    const hexHash = hash.toString(CryptoJS.enc.Hex)
    setEncryptedString(hexHash)

    // Algoritmo unidireccional (no se puede desencriptar)

  }
  const e_HMAC_SHA256 = () => {
    if (!key) return alert("You need add a key")

    const hash = CryptoJS.HmacSHA256(originalString, key)
    const hexHash = hash.toString(CryptoJS.enc.Hex)
    setEncryptedString(hexHash)

    // HMAC no es un algoritmo en si, sino una construccion criptografica, 
    // HMAC utiliza sha256 para encriptar, y sha256 es unidireccional
  }
  const e_PBKDF2 = () => {
    if (!iterations) return alert("You need add a value for iterations input")
    if (!password) return alert("You need add a value for password input")
    if (!salt) return alert("You need add a value for salt input")


    const key = CryptoJS.PBKDF2(password, CryptoJS.enc.Utf8.parse(salt), {
      keySize: 256 / 32,
      iterations: iterations
    })

    const encrypted = CryptoJS.AES.encrypt(originalString, key, {
      iv: CryptoJS.lib.WordArray.random(128 / 8)
    })

    setEncryptedString(encrypted.toString())
  }

  const e_DES = () => {
    if (!key) return alert("You need add a key")
    if (!iv) return alert("You need add an initial value")

    const newKey = CryptoJS.enc.Utf8.parse(key)
    const newIv = CryptoJS.enc.Utf8.parse(iv)

    const config = {
      iv: newIv,
      mode: CryptoJS.mode.CFB,
      padding: CryptoJS.pad.Pkcs7
    }

    const encrypted = CryptoJS.DES.encrypt(originalString, newKey, config)
    setEncryptedString(encrypted.toString())
  }
  const d_DES = () => {
    if (!key) return alert("You need add a key")
    if (!iv) return alert("You need add an initial value")

    const newIv = CryptoJS.enc.Utf8.parse(iv)
    const newKey = CryptoJS.enc.Utf8.parse(key)

    const config = {
      iv: newIv,
      mode: CryptoJS.mode.CFB,
      padding: CryptoJS.pad.Pkcs7
    }

    const decrypted = CryptoJS.DES.decrypt(originalHash, newKey, config)
    setDecryptedHash(decrypted.toString(CryptoJS.enc.Utf8))
  }

  const e_RABBIT = () => {
    if (!key) return alert("You need add a key")

    const encrypted = CryptoJS.Rabbit.encrypt(originalString, key);
    setEncryptedString(encrypted.toString())
  }
  const d_RABBIT = () => {
    if (!key) return alert("You need add a key")

    const decrypted = CryptoJS.Rabbit.decrypt(originalHash.toString(), key)
    setDecryptedHash(decrypted.toString(CryptoJS.enc.Utf8))
  }


  const handleEncrypt = () => {
    if (!originalString) alert("You need to add a unencrypted text")

    switch (algorithm) {
      case "aes":
        e_AES()
        break;
      case "md5":
        e_MD5()
        break;
      case "sha-1":
        e_SHA1()
        break;
      case "sha-2":
        e_SHA2()
        break;
      case "sha-3":
        e_SHA3()
        break;
      case "ripemd-160":
        e_RIPEMD160()
        break;
      case "hmac-sha256":
        e_HMAC_SHA256()
        break;
      case "pbkdf2":
        e_PBKDF2()
        break;
      case "des":
        e_DES()
        break;
      case "rabbit":
        e_RABBIT()
        break;
    }
  }
  const handleDecrypt = () => {
    if (
      algorithm === "md5" ||
      algorithm === "sha-1" ||
      algorithm === "sha-2" ||
      algorithm === "sha-3" ||
      algorithm === "ripemd-160" ||
      algorithm === "hmac-sha256") {
      return alert("This algorithm is one-way, so it cannot be decrypted")
    }
    if (!originalHash) return alert("You need to add a encrypted text")

    switch (algorithm) {
      case "aes":
        d_AES()
        break;
      case "pbkdf2":
        d_PBKDF2()
        break;
      case "des":
        d_DES()
        break;
      case "rabbit":
        d_RABBIT()
        break;
    }
  }

  const handleHistoryItemClick = (algorithm_, method, inputLog) => {
    console.log(algorithm)

    setAlgorithm(algorithm_)
    setEncryptMode(method === "encrypt" ? true : false)

    if (method === "encrypt") setOriginalString(inputLog.mainInput)
    else setOriginalHash(inputLog.mainInput)

    if (inputLog.key) setKey(inputLog.key)
    if (inputLog.password) setPassword(inputLog.password)
    if (inputLog.iv) setIv(inputLog.iv)
    if (inputLog.iterations) setIterations(inputLog.iterations)
    if (inputLog.salt) setSalt(inputLog.salt)
  }

  // Almacenar texto encriptado
  useEffect(() => {
    if (!encryptedString) return

    const hashes = JSON.parse(localStorage.getItem("text-cipher-history"))

    let inputLog = { mainInput: originalString }

    if (algorithm === "aes" || algorithm === "hmac-sha256" || algorithm === "rabbit") {
      inputLog = {
        ...inputLog,
        key
      }
    } else if (algorithm === "pbkdf2") {
      inputLog = {
        ...inputLog,
        password,
        salt,
        iterations
      }
    } else if (algorithm === "des") {
      inputLog = {
        ...inputLog,
        key,
        iv
      }
    }

    if (hashes) {
      setHistory([
        ...hashes,
        {
          algorithm,
          method: "encrypt",
          inputLog
        }
      ])

      localStorage.setItem("text-cipher-history",
        JSON.stringify([
          ...hashes,
          {
            algorithm,
            method: "encrypt",
            inputLog
          }
        ]))
    } else {
      setHistory([
        {
          algorithm,
          method: "encrypt",
          inputLog
        }
      ])

      localStorage.setItem("text-cipher-history",
        JSON.stringify([
          {
            algorithm,
            method: "encrypt",
            inputLog
          }
        ]))
    }
  }, [encryptedString])

  // Almacenar hash desencriptado
  useEffect(() => {
    if (!decryptedHash) return

    const hashes = JSON.parse(localStorage.getItem("text-cipher-history"))


    let inputLog = { mainInput: originalHash }

    if (algorithm === "aes" || algorithm === "rabbit") {
      inputLog = {
        ...inputLog,
        key
      }
    } else if (algorithm === "des") {
      inputLog = {
        ...inputLog,
        key,
        iv
      }
    }

    if (hashes) {
      setHistory([
        ...hashes,
        {
          algorithm,
          method: "decrypt",
          inputLog
        }
      ])

      localStorage.setItem("text-cipher-history",
        JSON.stringify([
          ...hashes,
          {
            algorithm,
            method: "decrypt",
            inputLog
          }
        ]))
    } else {
      setHistory([
        {
          algorithm,
          method: "decrypt",
          inputLog
        }
      ])
      localStorage.setItem("text-cipher-history",
        JSON.stringify([
          {
            algorithm,
            method: "decrypt",
            inputLog
          }
        ]))
    }
  }, [decryptedHash])

  // Recuperar historial
  useEffect(() => {
    if (localStorage.getItem("text-cipher-history")) {
      setHistory(JSON.parse(localStorage.getItem("text-cipher-history")))
    }
  }, [])



  // Limpiar historial 
  const handleClearHistory = () => {
    localStorage.removeItem("text-cipher-history")
    setHistory([])
  }


  const theme = darkMode ? "dark" : "light"

  return (
    <main className={theme}>
      <header>
        <h1>text cipher</h1>
        <h1 className='title-background'>U2FsdGVkX6F/du5Kj=Pn+2</h1>
        <>
          <input type='checkbox' id='darkmode-toggle' onClick={() => setDarkMode(!darkMode)} />
          <label for="darkmode-toggle" />
        </>
      </header>
      <section>
        <article>
          <div className='titles-container'>
            <h3>history</h3>
            <h3 className='clear-history-button' onClick={handleClearHistory}>clean</h3>
          </div>
          <div className='history-items-container'>
            {
              history.map((current, index) => (
                <HistoryItem
                  key={index}
                  algorithm={current.algorithm}
                  inputLog={current.inputLog}
                  method={current.method}
                  handleClick={() => handleHistoryItemClick(current.algorithm, current.method, current.inputLog)}
                />
              ))
            }
          </div>
        </article>
        <article>
          {
            encryptMode ?
              <div className='titles-container'>
                <h3>encrypt text</h3>
                <h3>|</h3>
                <h3 onClick={() => setEncryptMode(false)}>decrypt text</h3>
              </div> :
              <div className='titles-container'>
                <h3>decrypt text</h3>
                <h3>|</h3>
                <h3 onClick={() => setEncryptMode(true)}>encrypt text</h3>
              </div>
          }
          <div className='main-form'>
            <div className='unencrypted-form'>
              <label>
                {
                  encryptMode ?
                    "your text" :
                    "your hash"
                }
                <div className='submit-form' style={{ display: "flex" }}>
                  <input
                    onChange={e => encryptMode ? setOriginalString(e.target.value) : setOriginalHash(e.target.value)}
                    value={encryptMode ? originalString : originalHash}
                    placeholder={
                      encryptMode ?
                        'Hello world!..' :
                        'U2FsdGVkX1/HXqvWsqRge+nh1pdfrKe...'
                    }

                  />
                  <FaArrowUp onClick={() => encryptMode ? handleEncrypt() : handleDecrypt()} />
                </div>
              </label>
            </div>
            <div className='algorithm-selector'>
              {
                encryptMode ?
                  <label className='select-container'>
                    algorithm
                    <select onChange={e => setAlgorithm(e.target.value)} value={algorithm}>
                      <option value="aes">aes</option>
                      <option value="md5">md5</option>
                      <option value="sha-1">sha-1</option>
                      <option value="sha-2">sha-2 (256)</option>
                      <option value="sha-3">sha-3</option>
                      <option value="ripemd-160">ripemd-160</option>
                      <option value="hmac-sha256">hmac-sha256</option>
                      <option value="pbkdf2">pbkdf2</option>
                      <option value="des">des</option>
                      <option value="rabbit">rabbit</option>
                    </select>
                    <span className='custom-arrow' />
                  </label> :
                  <label className='select-container'>
                    algorithm
                    <select onChange={e => setAlgorithm(e.target.value)} value={algorithm}>
                      <option value="aes">aes</option>
                      <option value="des">des</option>
                      <option value="rabbit">rabbit</option>
                    </select>
                    <span className='custom-arrow' />
                  </label>
              }
            </div>
            <div className='algorithm-options'>
              {
                algorithm === "pbkdf2" ?
                  <>
                    <label>
                      password
                      <input
                        placeholder='password...'
                        onChange={e => setPassword(e.target.value)}
                        value={password}
                      />
                    </label>
                    {
                      <label className='salt-label'>
                        salt
                        <input
                          placeholder='salt...'
                          onChange={e => setSalt(e.target.value)}
                          value={salt}
                        />
                      </label>
                    }
                    <label className='iterations-label'>
                      iterations
                      <input
                        placeholder='iterations...'
                        onChange={e => setIterations(e.target.value)}
                        value={iterations}
                      />
                    </label>
                  </>
                  : algorithm === "hmac-sha256" || algorithm === "rabbit" || algorithm === "aes" ?
                    <label className='key-label'>
                      key
                      <input placeholder='your key...' onChange={e => setKey(e.target.value)} value={key} />
                    </label>
                    : algorithm === "des" ?
                      <>
                        <label className='key-label'>
                          key
                          <input placeholder='your key...' onChange={e => setKey(e.target.value)} value={key} />
                        </label>
                        <label className='key-label'>
                          initial value
                          <input placeholder='your iv...' onChange={e => setIv(e.target.value)} value={iv} />
                        </label>
                      </>
                      : undefined
              }
            </div>
          </div>
          <p className='algorithm-description'>
            {
              algorithm === "aes" ?
                algorithmsDescriptions.aes :
                algorithm === "md5" ?
                  algorithmsDescriptions.md5 :
                  algorithm === "sha-1" ?
                    algorithmsDescriptions.sha1 :
                    algorithm === "sha-2" ?
                      algorithmsDescriptions.sha2 :
                      algorithm === "sha-3" ?
                        algorithmsDescriptions.sha3 :
                        algorithm === "ripemd-160" ?
                          algorithmsDescriptions.ripemd160 :
                          algorithm === "hmac-sha256" ?
                            algorithmsDescriptions.hmacSha256 :
                            algorithm === "pbkdf2" ?
                              algorithmsDescriptions.pbkdf2 :
                              algorithm === "des" ?
                                algorithmsDescriptions.des :
                                algorithm === "rabbit" ?
                                  algorithmsDescriptions.rabbit :
                                  ""
            }
          </p>
        </article>
        <article e>
          <h3>your encrypted text</h3>
          <div className='encrypted-result'>
            <p>{encryptMode ? encryptedString : decryptedHash}</p>
          </div>
          <h1>{generatedSalt}</h1>
        </article>
      </section>
      <footer>
        <div onClick={handleOpenGitHub}>
          <FaGithub />
          Elias Espondaburu
        </div>
      </footer>
    </main>
  )
}

export default App
