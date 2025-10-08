package database

import (
	"context"
	"github.com/jackc/pgx/v5"
	"os"
    "errors"

	"github.com/jackc/pgconn"
	
	//local
	"secureVault/structures"
)


func connectDB() (*pgx.Conn, error){
	connString := os.Getenv("DB_URL")
	// Parse DSN
	connConfig, err := pgx.ParseConfig(connString)
	if err != nil {
		// log.Fatalf("Unable to parse config: %v", err)
		return nil, err
	}
	// 🔑 Disable prepared statements
	connConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	// Connect
	conn, err := pgx.ConnectConfig(context.Background(), connConfig)
	if err != nil {
		// log.Fatalf("Failed to connect: %v", err)
		return nil, err
	}
	
	return conn, err
}

func InsertUser(u structures.User) (bool, string){
	conn, err := connectDB()
	if conn==nil{
		return false, "Cannot Connect To database"
	}
	defer conn.Close(context.Background())
	_, err = conn.Exec(
		context.Background(),
		`INSERT INTO users (id, pwdhash, sizeused, isadmin) VALUES ($1, $2, $3, $4)`,
		u.ID, u.PwdHash, u.SizeUsed, u.IsAdmin,
	)
	if err != nil {
		var pgErr *pgconn.PgError
        if errors.As(err, &pgErr) && pgErr.Code == "23505" {
            // 23505 = unique_violation
            return false, "User already exists"
        }
		return false, "There is some unknown error: "+err.Error()
	}
	return true, ""
}

func GetUserData(ID string) (structures.User, bool){
	var u structures.User
	conn, err := connectDB()
	if conn==nil || err!=nil{
		return u, false
	}
	defer conn.Close(context.Background())


	err = conn.QueryRow(
		context.Background(),
		"SELECT id, pwdhash, sizeused, isadmin FROM users WHERE id=$1",
		ID,
	).Scan(&u.ID, &u.PwdHash, &u.SizeUsed, &u.IsAdmin)

	if err != nil {
		return u, false
	}

	return u, true
}

func ChangeFilePermision(msg structures.Message) (bool, string) {
	conn, err := connectDB()
	if conn==nil || err!=nil{
		return false, "Cannot connect to server"
	}
	defer conn.Close(context.Background())

	cmd, err := conn.Exec(
		context.Background(),
		`UPDATE links SET access=$1, downloads=0 WHERE id=$2 AND file_id=$3`,
		msg.NewAccess, msg.ID, msg.FileId,
	)
	if err != nil {
		return false, err.Error()
	}
	if cmd.RowsAffected()==0 {
		return false, "File not found"
	}
	return true, ""
}

func Upload(msg structures.Message) (bool, string){
	conn, err := connectDB()
	if conn==nil{
		return false, "Cannot Connect database"
	}
	defer conn.Close(context.Background())

	//Check for file name conflict
	var isFileNameConflict bool = false
	err = conn.QueryRow(
		context.Background(),
		"SELECT EXISTS (SELECT 1 FROM links WHERE id = $1 AND filename = $2)",
		msg.ID, msg.FileName,
	).Scan(&isFileNameConflict)
	if err != nil {
		return false, "There is some unknown error"
	}
	if isFileNameConflict==true{
		return false, "Duplicate file name"
	}

	// Check if the file in database already exists
	var isFileExist bool = false
	err = conn.QueryRow(
		context.Background(),
		"SELECT EXISTS(SELECT 1 FROM files WHERE hash = $1)",
		msg.FileHash,
	).Scan(&isFileExist)
	if err != nil {
		return false, "There is some unknown error"
	}



	//Insert the file in database if not exist
	if isFileExist==false{
		_, err = conn.Exec(
			context.Background(),
			`INSERT INTO files(hash, size, data, occurance) VALUES($1, $2, $3, $4)`,
			msg.FileHash, len(msg.FileBytes), msg.FileBytes, 0,
		)
		if err != nil{
			return false, "There is error, cannot insert file to database"
		}
	}

	// Link the user with the file
	_, err = conn.Exec(
		context.Background(),
		`INSERT INTO links(hash, id, access, downloads, filename, size, "time") VALUES($1, $2, $3, $4, $5, $6, NOW())`,
		msg.FileHash, msg.ID, "PRIVATE", 0, msg.FileName, len(msg.FileBytes),
	)
	if err != nil{
		return false, err.Error()
	}
	return true, ""
}

func GetSingleLinkInfo(msg structures.Message) (structures.Link, bool, string){
	conn, err := connectDB()
	var linkInfo structures.Link
	if conn==nil{
		return linkInfo, false, "Cannot Connect database"
	}
	defer conn.Close(context.Background())


	err = conn.QueryRow(
		context.Background(),
		"SELECT hash, id, access, downloads, filename, time, file_id FROM links WHERE id=$1 and file_id=$2",
		msg.ID, msg.FileId,
	).Scan(&linkInfo.Hash, &linkInfo.ID, &linkInfo.Access, &linkInfo.Downloads, &linkInfo.FileName, &linkInfo.Time, &linkInfo.FileId)

	if err != nil {
        if err == pgx.ErrNoRows {
            return linkInfo, false, "No link found"
        }
        return linkInfo, false, err.Error()
    }

	return linkInfo, true, ""
}

func GetFileData(hash string, id string, fileId int, isPublicAccess bool) ([]byte, bool, string){
	conn, err := connectDB()
	var fileBytes []byte
	if conn==nil{
		return fileBytes, false, "Cannot Connect database"
	}
	defer conn.Close(context.Background())

	// Begin transaction
	tx, err := conn.Begin(context.Background())
	if err != nil {
		return fileBytes, false, "Failed to begin transaction: " + err.Error()
	}
	defer tx.Rollback(context.Background()) // rollback on any early return

	if (isPublicAccess == true){ //Increment the download if public access
		_, err = tx.Exec(
			context.Background(),
			`UPDATE links SET downloads = downloads+1 WHERE hash=$1 AND id=$2 AND file_id=$3`,
			hash, id, fileId,
		)
		if err != nil {
			return fileBytes, false, err.Error()
		}
	}

	err = tx.QueryRow(
		context.Background(),
		"SELECT data FROM files WHERE hash=$1",
		hash,
	).Scan(&fileBytes)

	if err != nil {
        if err == pgx.ErrNoRows {
            return fileBytes, false, "File Not Found"
        }
        return fileBytes, false, err.Error()
    }

	// Commit transaction (both queries succeed together)
	err = tx.Commit(context.Background()) 
	if err != nil {
		return fileBytes, false, "Failed to commit transaction: " + err.Error()
	}

	return fileBytes, true, ""
}

func GetLink(msg structures.Message) ([]structures.Link, bool, string) {
	conn, err := connectDB()
	var allFileInfo []structures.Link
	if conn == nil {
		return allFileInfo, false, "Cannot Connect database"
	}
	defer conn.Close(context.Background())

	var rows pgx.Rows

	// If user is admin get all the links
	if msg.IsAdmin {
		rows, err = conn.Query(
			context.Background(),
			`SELECT hash, id, access, downloads, filename, time, file_id, size FROM links`,
		)
	} else {
		// If user is not admin → get only their links
		rows, err = conn.Query(
			context.Background(),
			`SELECT hash, id, access, downloads, filename, time, file_id, size FROM links WHERE id=$1`,
			msg.ID,
		)
	}

	if err != nil {
		return allFileInfo, false, err.Error()
	}
	defer rows.Close()

	for rows.Next() {
		var l structures.Link
		err := rows.Scan(&l.Hash, &l.ID, &l.Access, &l.Downloads, &l.FileName, &l.Time, &l.FileId, &l.Size)
		if err != nil {
			return allFileInfo, false, err.Error()
		}
		allFileInfo = append(allFileInfo, l)
	}

	if rows.Err() != nil {
		return allFileInfo, false, rows.Err().Error()
	}

	return allFileInfo, true, ""
}

func DeleteFile(msg structures.Message) (bool, string){
	conn, err := connectDB()
	if conn == nil {
		return false, "Cannot Connect database"
	}
	defer conn.Close(context.Background())

	cmd, err := conn.Exec(
		context.Background(),
		`DELETE FROM links WHERE id=$1 AND file_id=$2`,
		msg.ID, msg.FileId,
	)
	if err != nil {
		return false, err.Error()
	}
	if cmd.RowsAffected() == 0 {
		return false, "No file found with given ID and fileId"
	}

	return true, ""
}

func DeleteAccount(u structures.User) (bool, string){
	conn, err := connectDB()
	if conn == nil {
		return false, "Cannot Connect database"
	}
	defer conn.Close(context.Background())

	cmd, err := conn.Exec(
		context.Background(),
		`DELETE FROM users WHERE id=$1`,
		u.ID,
	)
	if err != nil {
		return false, err.Error()
	}
	if cmd.RowsAffected() == 0 {
		return false, "User not found"
	}

	return true, ""
}

