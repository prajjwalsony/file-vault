package functions

import (
	"net/http"
	"encoding/json"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"
	"strings"
	"errors"

	"crypto/rand"
	"crypto/rsa"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	// "crypto/sha1"
	"encoding/pem"
	"crypto/x509"

	"github.com/golang-jwt/jwt/v5"

	// local
	"secureVault/database"
	"secureVault/structures"
)

const MAX_STORAGE_LIMIT = 10*1024*1024

func GetFile(w http.ResponseWriter, r *http.Request){
	//Expected (get) : /getFile?id=<uid>&fileId=<fid>&action=<view/download>
	//Expected (post) json : {"fileId", "action"(view, download)}

	// Extracting information from request
	var msg structures.Message
	var isPrivateAccess bool = false
	if r.Method==http.MethodPost{
		var status bool
		var errMsg string
		status, msg, errMsg = processRequest(r)
		if status==false{
			http.Error(w, fmt.Sprintf(`{"ERROR":"%s"}`, errMsg), http.StatusInternalServerError)
			return
		}
		isPrivateAccess = true
	} else if r.Method==http.MethodGet {
		msg.ID = r.URL.Query().Get("id")
		msg.Action = r.URL.Query().Get("action")
		fid, err := strconv.Atoi(r.URL.Query().Get("fileId"))
    	if err != nil {
        	http.Error(w, `{"ERROR":"Invalid fileId"}`, http.StatusBadRequest)
        	return
    	}
    	msg.FileId = fid
	} else {
		http.Error(w, `{"ERROR":"Invalid request method"}`, http.StatusMethodNotAllowed)
		return
	}

	// Validate the actions
	if (msg.Action!="view" && msg.Action!="download"){
		http.Error(w, `{"ERROR":"Invalid action"}`, http.StatusBadRequest)
        return
	}

	// Get the file information
	linkInfo, status, errMsg := database.GetSingleLinkInfo(msg) //(structures.Link, bool, string)
	if !status {
		http.Error(w, fmt.Sprintf(`{"ERROR":"%s"}`, errMsg), http.StatusBadRequest)
		return
	}

	// Get the user information from database and verify access
	if (linkInfo.Access=="PRIVATE" && isPrivateAccess==false){ //if cliet is not the owner	
		http.Error(w, `{"ERROR":"Access Denied"}`, http.StatusBadRequest)
        return
	}

	// Get the file from database
	var fileBytes []byte
	if r.Method==http.MethodPost { //private access
		fileBytes, status, errMsg = database.GetFileData(linkInfo.Hash, linkInfo.ID, linkInfo.FileId, false) //([]bytes, bool, string)
	} else if r.Method==http.MethodGet { //public access
		fileBytes, status, errMsg = database.GetFileData(linkInfo.Hash, linkInfo.ID, linkInfo.FileId, true) //([]bytes, bool, string)
	}
	if status==false{
		http.Error(w, fmt.Sprintf(`{"ERROR":"%s"}`, errMsg), http.StatusBadRequest)
    	return
	}

	// Modify the response header and send the file
	w.Header().Set("Access-Control-Allow-Origin", "*") // or your frontend origin
	w.Header().Set("Access-Control-Expose-Headers", "Content-Disposition")

	if msg.Action=="download" {
		w.Header().Set("Content-Disposition", "attachment")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", linkInfo.FileName))
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	if msg.Action=="view" {
		mimeType := http.DetectContentType(fileBytes)
		w.Header().Set("Content-Type", mimeType)
		w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", linkInfo.FileName))
	}

	w.WriteHeader(http.StatusOK)
	_, err := w.Write(fileBytes)
	if err != nil {
		http.Error(w, `{"ERROR":"Failed to send file"}`, http.StatusInternalServerError)
		return
	}
}

func UploadFile(w http.ResponseWriter, r *http.Request){
	//Expected formData : {"file"}
	if r.Method != http.MethodPost{
		http.Error(w, `{"ERROR":"Invalid request method"}`, http.StatusMethodNotAllowed)
		return
	}

	// verify the zwt header and fill the data in msg
	jwt := r.Header.Get("Authorization")
    if jwt == "" {
        http.Error(w, `{"ERROR":"Missing JWT"}`, http.StatusUnauthorized)
        return
    }
    isValid, id, isAdmin, serverTokenBase64, errMsg := verifyToken(jwt)
    if !isValid {
        http.Error(w, fmt.Sprintf(`{"ERROR":"Invalid JWT: %s"}`, errMsg), http.StatusUnauthorized)
        return
    }


	// Decrypt the session key
    serverKeyEnv := os.Getenv("AES_SERVER_KEY")
    if len(serverKeyEnv) < 32 {
        http.Error(w, `{"ERROR":"Server key configuration error"}`, http.StatusInternalServerError)
        return
    }
    serverKey := []byte(serverKeyEnv)[:32]

    serverTokenBytes, err := base64.StdEncoding.DecodeString(serverTokenBase64)
    if err != nil {
        http.Error(w, `{"ERROR":"Failed to decode server token"}`, http.StatusBadRequest)
        return
    }

    sessionKey, err := decryptAES(serverTokenBytes, serverKey)
    if err != nil {
        http.Error(w, `{"ERROR":"Failed to decrypt session key"}`, http.StatusBadRequest)
        return
    }
	temp := sessionKey
	sessionKey = temp

	// Read and decrypt uploaded file ---
    var msg structures.Message
	file, handler, err := r.FormFile("file")
	if err != nil {
        http.Error(w, `{"ERROR":"Error retrieving file"}`, http.StatusBadRequest)
        return
    }
	defer file.Close()
	msg.FileBytes, err = io.ReadAll(file)
	msg.FileName = handler.Filename
	msg.ID = id
    msg.IsAdmin = isAdmin
	msg.FileId = 0

	// Check for overall size limit exceeds
	u, status := database.GetUserData(msg.ID)
	if status==false{
		http.Error(w, "There is some unknown error!!!", http.StatusInternalServerError)
    	return
	}
	if (u.SizeUsed+int(handler.Size) > MAX_STORAGE_LIMIT){
		http.Error(w, "Your Storage Limit Exceeded!!!", http.StatusBadRequest)
    	return
	}


	//Hashing
	var hashArray [64]byte = sha512.Sum512(msg.FileBytes)
	var hashSlice []byte = hashArray[:]
	msg.FileHash = hex.EncodeToString(hashSlice)

	status, errMsg = database.Upload(msg)


	if status == false {
    	http.Error(w, fmt.Sprintf(`{"ERROR":"%s"}`, errMsg), http.StatusBadRequest)
    	return
	}

	json.NewEncoder(w).Encode(map[string]string{"ERROR":""})
}

func GetFileList(w http.ResponseWriter, r *http.Request){
	//Expected json : {}
	if r.Method != http.MethodPost{
		http.Error(w, `{"ERROR":"Invalid request method"}`, http.StatusMethodNotAllowed)
		return
	}

	// Get the information from request
	status, msg, errMsg := processRequest(r)
	if status==false{
		http.Error(w, fmt.Sprintf(`{"ERROR":"%s"}`, errMsg), http.StatusInternalServerError)
		return
	}

	// Get the list of all valid links
	var links []structures.Link
	links, status, errMsg = database.GetLink(msg) // ([]structures.Link, bool, string)
	if !status {
		http.Error(w, fmt.Sprintf(`{"ERROR":"%s"}`, errMsg), http.StatusInternalServerError)
		return
	}

	

	// Encrypt the links before sending
	linksJSON, err := json.Marshal(links)
	if err != nil {
		http.Error(w, `{"ERROR":"Failed to marshal links"}`, http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(map[string]string{"ERROR":"", "data":string(linksJSON)})
	if err!=nil {
		http.Error(w, `{"ERROR":"Failed to encode response"}`, http.StatusInternalServerError)
		return
	} else{
		return
	}

	encryptedLinks, err := encryptAES(linksJSON, msg.SessionKey)

	if err != nil {
		http.Error(w, `{"ERROR":"Failed to encrypt links"}`, http.StatusInternalServerError)
		return
	}

	fmt.Println(base64.StdEncoding.EncodeToString(encryptedLinks))
	fmt.Println(base64.StdEncoding.EncodeToString(msg.SessionKey))
	err = json.NewEncoder(w).Encode(map[string]string{"ERROR":"", "data":base64.StdEncoding.EncodeToString(encryptedLinks)})
	if err!=nil {
		http.Error(w, `{"ERROR":"Failed to encode response"}`, http.StatusInternalServerError)
		return
	}

	// w.Header().Set("Content-Type", "text/plain")
    // w.Write([]byte(base64.StdEncoding.EncodeToString(encryptedLinks)))
}

func CreateAccount(w http.ResponseWriter, r *http.Request) {
	//Expected json : {"id", "pwd"}
    if r.Method != http.MethodPost {
        http.Error(w, `{"ERROR":"Invalid request method"}`, http.StatusMethodNotAllowed)
        return
    }
    
    // --- Step 1: get the incoming payload ---
    encryptedBase64, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, `{"ERROR":"Failed to read body"}`, http.StatusBadRequest)
        return
    }

	// Decode Base64
	ciphertext, err := base64.StdEncoding.DecodeString(string(encryptedBase64))
	if err != nil {
		http.Error(w, `{"ERROR":"failed to decode base64"}`, http.StatusBadRequest)
        return
	}

	// Parse PEM private key
	privateKeyPEM := os.Getenv("RSA_PRIVATE_KEY")
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		http.Error(w, `{"ERROR":"failed to decode PEM block containing private key"}`, http.StatusBadRequest)
        return
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		http.Error(w, `{"ERROR":"failed to parse RSA private key"}`, http.StatusBadRequest)
        return
	}

	// Decrypt using OAEP + SHA256
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		http.Error(w, `{"ERROR":"decryption failed"}`, http.StatusBadRequest)
        return
	}

    
    // Expected decrypted JSON: {"id":"...", "pwd":"..."}
    var msg structures.Message
    if err := json.Unmarshal(plaintext, &msg); err != nil {
        http.Error(w, `{"ERROR":"Invalid decrypted JSON"}`, http.StatusBadRequest)
        return
    }
    
    // Basic input validation
    if msg.ID == "" || msg.Pwd == "" {
        http.Error(w, `{"ERROR":"Missing credentials"}`, http.StatusBadRequest)
        return
    }

    // --- Step 2: Hash the password before storing ---
    hashedPwd := sha256.Sum256([]byte(msg.Pwd))
    hashedPwdHex := fmt.Sprintf("%x", hashedPwd) // Convert to hex string

    // --- Step 3: Create user with hashed password ---
    var u structures.User = structures.User{
        ID:       msg.ID,
        PwdHash:  hashedPwdHex, // Store hashed password
        SizeUsed: 0,
        IsAdmin:  false,
    }

	
    status, errMsg := database.InsertUser(u)
    if !status {
		http.Error(w, fmt.Sprintf(`{"ERROR":"%s"}`, errMsg), http.StatusConflict)
        return
    }

    // --- Step 4: Return success response ---
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"ERROR": ""})
}

// Login handles user authentication
func Login(w http.ResponseWriter, r *http.Request) {
	//Expected json : {"id", "pwd"}
    if r.Method != http.MethodPost {
        http.Error(w, `{"ERROR":"Invalid request method"}`, http.StatusMethodNotAllowed)
        return
    }
    
    // --- Step 1: get the incoming payload ---
    encryptedBase64, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, `{"ERROR":"Failed to read body"}`, http.StatusBadRequest)
        return
    }

	// Decode Base64
	ciphertext, err := base64.StdEncoding.DecodeString(string(encryptedBase64))
	if err != nil {
		http.Error(w, `{"ERROR":"failed to decode base64"}`, http.StatusBadRequest)
        return
	}

	// Parse PEM private key
	privateKeyPEM := os.Getenv("RSA_PRIVATE_KEY")
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		http.Error(w, `{"ERROR":"failed to decode PEM block containing private key"}`, http.StatusBadRequest)
        return
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		http.Error(w, `{"ERROR":"failed to parse RSA private key"}`, http.StatusBadRequest)
        return
	}

	// Decrypt using OAEP + SHA256
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		http.Error(w, `{"ERROR":"decryption failed"}`, http.StatusBadRequest)
        return
	}
    
    // Expected decrypted JSON: {"id":"...", "pwd":"..."}
    var msg structures.Message
    if err := json.Unmarshal(plaintext, &msg); err != nil {
        http.Error(w, `{"ERROR":"Invalid decrypted JSON"}`, http.StatusBadRequest)
        return
    }
    
    // Basic input validation
    if msg.ID == "" || msg.Pwd == "" {
        http.Error(w, `{"ERROR":"Missing credentials"}`, http.StatusBadRequest)
        return
    }
    
    // --- Step 2: Get user from DB ---
    u, status := database.GetUserData(msg.ID)
    if !status {
        http.Error(w, `{"ERROR":"User doesn't exist"}`, http.StatusUnauthorized)
        return
    }
    
    // --- Step 3: Hash password & compare ---
    hashedPwd := sha256.Sum256([]byte(msg.Pwd))
    hashedPwdHex := fmt.Sprintf("%x", hashedPwd) // Convert to hex string
    
    // Compare with stored hash (assuming DB stores hex-encoded hash)
    if hashedPwdHex != u.PwdHash {
        http.Error(w, `{"ERROR":"Wrong Password"}`, http.StatusUnauthorized)
        return
    }
    
    // --- Step 4: Generate session key ---
    sessionKey := make([]byte, 32) // AES-256 key
    if _, err := rand.Read(sessionKey); err != nil {
        http.Error(w, `{"ERROR":"Failed to generate session key"}`, http.StatusInternalServerError)
        return
    }
    
    // --- Step 5: Encrypt session key with ServerKey ---
    serverKeyEnv := os.Getenv("AES_SERVER_KEY")
    if len(serverKeyEnv) < 32 {
        http.Error(w, `{"ERROR":"Server key configuration error"}`, http.StatusInternalServerError)
        return
    }
    serverKey := []byte(serverKeyEnv)[:32] // Safe to slice now
    
    serverToken, err := encryptAES(sessionKey, serverKey) // Assuming you have an encryptAES helper
    if err != nil {
        http.Error(w, `{"ERROR":"Failed to encrypt server token"}`, http.StatusInternalServerError)
        return
    }
    
    // --- Step 6: Encrypt session key with User password ---
    userPwdKey := sha256.Sum256([]byte(msg.Pwd)) // derive 32-byte key
    userToken, err := encryptAES(sessionKey, userPwdKey[:]) // Assuming you have an encryptAES helper
    if err != nil {
        http.Error(w, `{"ERROR":"Failed to encrypt user token"}`, http.StatusInternalServerError)
        return
    }
    
    // --- Step 7: Create JWT ---
    jwtSecret := os.Getenv("JWT_SIGN_KEY")
    if jwtSecret == "" {
        http.Error(w, `{"ERROR":"JWT secret not configured"}`, http.StatusInternalServerError)
        return
    }
    
    claims := jwt.MapClaims{
        "ID":          u.ID,
        "isAdmin":     u.IsAdmin,
        "exp":         time.Now().Add(30 * time.Minute).Unix(), // Standard expiration claim
        "serverToken": base64.StdEncoding.EncodeToString(serverToken),
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    signedJWT, err := token.SignedString([]byte(jwtSecret))
    if err != nil {
        http.Error(w, `{"ERROR":"Failed to sign JWT"}`, http.StatusInternalServerError)
        return
    }
    
    // --- Step 8: Respond with JWT in header and userToken as plaintext content ---
    w.Header().Set("Authorization", signedJWT)
    w.Header().Set("Content-Type", "text/plain")
    w.Write([]byte(base64.StdEncoding.EncodeToString(userToken)))
}


func ChangeAccess(w http.ResponseWriter, r *http.Request){
	//Expected json : {"fileId", "newAccess"}
	if r.Method != http.MethodPost{
		http.Error(w, `{"ERROR":"Invalid request method"}`, http.StatusMethodNotAllowed)
		return
	}

	// Get the information from request
	var status, msg, errMsg = processRequest(r)
	if status==false{
		http.Error(w, fmt.Sprintf(`{"ERROR":"%s"}`, errMsg), http.StatusInternalServerError)
		return
	}
	if (msg.NewAccess!="PUBLIC" && msg.NewAccess!="PRIVATE"){
		http.Error(w, `{"ERROR":"Invalid Request"}`, http.StatusBadRequest)
		return
	}


	// Change Access
	status, errMsg = database.ChangeFilePermision(msg)
	


	if !status {
		http.Error(w, fmt.Sprintf(`{"ERROR":"%s"}`, errMsg), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"ERROR":""})
}

func DeleteFile(w http.ResponseWriter, r *http.Request){
	//Expected json : {"fileId"}
	if r.Method != http.MethodPost{
		http.Error(w, `{"ERROR":"Invalid request method"}`, http.StatusMethodNotAllowed)
		return
	}

	// Get the information from request
	status, msg, errMsg := processRequest(r)
	if status==false{
		http.Error(w, fmt.Sprintf(`{"ERROR":"%s"}`, errMsg), http.StatusInternalServerError)
		return
	}

	// Delete the file
	status, errMsg = database.DeleteFile(msg)
	if !status {
		http.Error(w, fmt.Sprintf(`{"ERROR":"%s"}`, errMsg), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"ERROR":""})
}

func DeleteAccount(w http.ResponseWriter, r *http.Request){
	//Expected json : {"pwd}
	if r.Method != http.MethodPost{
		http.Error(w, `{"ERROR":"Invalid request method"}`, http.StatusMethodNotAllowed)
		return
	}

	// Get the information from request
	status, msg, errMsg := processRequest(r)
	if status==false{
		http.Error(w, fmt.Sprintf(`{"ERROR":"%s"}`, errMsg), http.StatusInternalServerError)
		return
	}

	 // --- Step 3: Hash password & compare ---
	 u, status := database.GetUserData(msg.ID) //(structures.User, bool)
	if status==false{
		http.Error(w, `{"ERROR":"Either user doen't exist OR There is some unknown error"}`, http.StatusBadRequest)
        return
	}

    hashedPwd := sha256.Sum256([]byte(msg.Pwd))
    hashedPwdHex := fmt.Sprintf("%x", hashedPwd) // Convert to hex string
    
    // Compare with stored hash (assuming DB stores hex-encoded hash)
    if hashedPwdHex != u.PwdHash {
        http.Error(w, `{"ERROR":"Wrong Password"}`, http.StatusUnauthorized)
        return
    }

	// Delete the file
	status, errMsg = database.DeleteAccount(u)
	if !status {
		http.Error(w, fmt.Sprintf(`{"ERROR":"%s"}`, errMsg), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"ERROR":""})
}

func GetPublicKey(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodGet {
		http.Error(w, `{"ERROR":"Invalid request method"}`, http.StatusMethodNotAllowed)
		return
	}

    // 1. Get the raw key from the environment variable, which contains literal "\\n" characters.
    rawKey := os.Getenv("RSA_PUBLIC_KEY")

    // 2. Replace all occurrences of the two-character string "\\n" with a single newline character "\n".
    // This creates a correctly formatted multi-line PEM string.
    formattedKey := strings.ReplaceAll(rawKey, "\\n", "\n")

    // 3. Send the properly formatted key as a plain text response.
    w.Header().Set("Content-Type", "text/plain")
    w.WriteHeader(http.StatusOK)
    fmt.Fprint(w, formattedKey)
}

func GetUserInfo(w http.ResponseWriter, r *http.Request) {
	// This endpoint uses JWT for authentication, no request body is needed.
	if r.Method != http.MethodPost {
		http.Error(w, `{"ERROR":"Invalid request method"}`, http.StatusMethodNotAllowed)
		return
	}

	// 1. Authenticate the user and get their info using the JWT from the header.
	// The processRequest function handles JWT verification and extracts the user ID.
	status, msg, errMsg := processRequest(r)
	if !status {
		http.Error(w, fmt.Sprintf(`{"ERROR":"%s"}`, errMsg), http.StatusUnauthorized)
		return
	}

	// 2. The user is now authenticated. Fetch their full, up-to-date data from the database.
	// We use msg.ID which was securely extracted from the validated JWT.
	u, dbStatus := database.GetUserData(msg.ID)
	if !dbStatus {
		// This is an unlikely edge case where a user with a valid JWT doesn't exist in the DB.
		http.Error(w, `{"ERROR":"User not found"}`, http.StatusNotFound)
		return
	}

	// 3. Prepare the user information for the response.
	// CRITICAL: Never include the password hash (u.PwdHash) in the response.
	userInfo := map[string]interface{}{
		"ERROR":    "",
		"id":       u.ID,
		"SizeUsed": u.SizeUsed,
		"IsAdmin":  u.IsAdmin,
	}

	// 4. Send the user information as a JSON response.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(userInfo)
	if err != nil {
		// This would be an internal server error if encoding fails.
		http.Error(w, `{"ERROR":"Failed to encode response"}`, http.StatusInternalServerError)
	}
}



// -------------------------------------------Helper Functions-------------------------------------------------------

// Helper function to parse RSA private key from PEM string
func parseRSAPrivateKey() (*rsa.PrivateKey, error) {
    privateKeyPEM := os.Getenv("RSA_PRIVATE_KEY")
    if privateKeyPEM == "" {
        return nil, fmt.Errorf("RSA_PRIVATE_KEY environment variable not set")
    }

    // Replace escaped newlines with actual newlines to fix formatting from .env files
    // This makes the parser more robust.
    privateKeyPEM = strings.ReplaceAll(privateKeyPEM, `\n`, "\n")

    // Decode PEM block
    block, _ := pem.Decode([]byte(privateKeyPEM))
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM block containing private key")
    }

    // The rest of the function remains the same...
    privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
        if err != nil {
            return nil, fmt.Errorf("failed to parse private key: %v", err)
        }
        
        rsaKey, ok := parsedKey.(*rsa.PrivateKey)
        if !ok {
            return nil, fmt.Errorf("not an RSA private key")
        }
        return rsaKey, nil
    }

    return privateKey, nil
}

// AES encryption function
func encryptAES(plaintext []byte, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    
    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := rand.Read(iv); err != nil {
        return nil, err
    }
    
    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
    return ciphertext, nil
}

// AES decryption
func decryptAES(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV is the first block of the ciphertext.
	// We must have at least one block size of data to proceed.
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// JWT token verification(or user verification)
//verification status, ID, isAdmin, sessionKey, error
func verifyToken(JWT string) (bool, string, bool, string, string) {
    // 1. Get the same secret key used for signing
    jwtSecret := os.Getenv("JWT_SIGN_KEY")
    if jwtSecret == "" {
        return false, "", false, "", "JWT secret not configured on server"
    }
    jwtSecretBytes := []byte(jwtSecret)

    // 2. Parse the token
    token, err := jwt.Parse(JWT, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return jwtSecretBytes, nil
    })

    if err != nil {
        return false, "", false, "", err.Error()
    }

    // 3. Extract claims if valid
    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        // ID (string, not float64)
        id, ok := claims["ID"].(string)
        if !ok {
            return false, "", false, "", "ID claim is missing or not a string"
        }

        // isAdmin
        isAdmin, ok := claims["isAdmin"].(bool)
        if !ok {
            return false, "", false, "", "isAdmin claim is missing or not a boolean"
        }

        // serverToken (base64 string)
        serverToken, ok := claims["serverToken"].(string)
        if !ok {
            return false, "", false, "", "serverToken claim is missing or not a string"
        }

        return true, id, isAdmin, serverToken, ""
    }

    return false, "", false, "", "token is invalid or claims are malformed"
}

func processRequest(r *http.Request) (bool, structures.Message, string){
	var msg structures.Message

	// --- 1. Get the Authorization header (JWT) ---
	jwt := r.Header.Get("Authorization")
	if jwt == "" {
		return false, msg, "missing Authorization header"
	}

	// --- 2. Verify JWT and extract claims ---
	valid, id, isAdmin, serverTokenBase64, errMsg := verifyToken(jwt)
	if !valid {
		return false, msg, "invalid JWT: " + errMsg
	}

	// --- 2.5. Fill in JWT info for convenience ---
	msg.ID = id
	msg.IsAdmin = isAdmin
	
	// --- 3. Decode the serverToken (AES-encrypted session key) ---
	serverKeyEnv := os.Getenv("AES_SERVER_KEY")
	if len(serverKeyEnv) < 32 {
		return false, msg, "server key not configured"
	}
	serverKey := []byte(serverKeyEnv)[:32] // AES-256
	
	serverTokenBytes, err := base64.StdEncoding.DecodeString(serverTokenBase64)
	if err != nil {
		return false, msg, "failed to base64 decode serverToken"
	}
	
	sessionKey, err := decryptAES(serverTokenBytes, serverKey)
	if err != nil {
		return false, msg, "failed to decrypt serverToken"
	}
	msg.SessionKey = sessionKey
	// fmt.Println(base64.StdEncoding.EncodeToString(sessionKey))
	// --- 4. Read and decrypt request body ---
	encryptedBody, err := io.ReadAll(r.Body)
	if len(encryptedBody) == 0 {
		return true, msg, ""
	}
	if err != nil {
		return false, msg, "failed to read request body"
	}
	
	ciphertext, err := base64.StdEncoding.DecodeString(string(encryptedBody))
	if err != nil {
		return false, msg, "failed to base64 decode body"
	}
	
	plaintext, err := decryptAES(ciphertext, sessionKey)
	if err != nil {
		return false, msg, "failed to decrypt request body"
	}

	// --- 5. Map JSON body into msg ---
	plaintext = []byte(strings.TrimSpace(string(plaintext)))
	err = json.Unmarshal(plaintext, &msg)
	if err != nil {
		return false, msg, "invalid decrypted JSON: " + err.Error()
	}

	

	return true, msg, ""

}

func printMessage(msg structures.Message){
	fmt.Println("ID:", msg.ID)
	fmt.Println("Pwd:", msg.Pwd)
	fmt.Println("NewAccess:", msg.NewAccess)
	fmt.Println("FileHash:", msg.FileHash)
	fmt.Println("FileBytes:", msg.FileBytes)
	fmt.Println("FileName:", msg.FileName)
	fmt.Println("FileId:", msg.FileId)
	fmt.Println("Action:", msg.Action)
	fmt.Println("IsAdmin:", msg.IsAdmin)
}