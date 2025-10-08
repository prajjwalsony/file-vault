package structures

// import(
// 	"encoding/json"
// )

type Message struct{
	ID string `json:"id"`
	Pwd string `json:"pwd"`
	NewAccess string `json:"newAccess"`
	FileHash string `json:"fileHash"`
	FileBytes []byte `json:"fileBytes"`
	FileName string `json:"fileName"`
	FileId int `json:"fileId"`
	Action string `json:"action"` //view or download
	IsAdmin bool `json:"isAdmin"`
	SessionKey []byte
}

type File struct {
	Hash      string
	Size      int
	Data      string
	Occurance int
}

type Link struct {
	Hash      string
	ID        string
	FileId    int
	Access    string   // false = private, true = public
	Downloads int
	FileName  string
	Size      int
	Time      string
}


type User struct {
	ID       string
	PwdHash      string
	SizeUsed int
	IsAdmin  bool
}