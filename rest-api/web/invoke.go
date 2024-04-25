package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"golang.org/x/crypto/bcrypt"
)

const (
	loginSuccess                  = 200
	loginFailedInvalidCredentials = 401
	loginFailedInternalError      = 500
)

func TodayDateTime() string {
	current := time.Now().UTC()
	formattedDate := current.Format("2006-01-02T15:04:05.000Z")
	return formattedDate
}

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

type SignedDetails struct {
	RollNo string
	jwt.StandardClaims
}

var SECRET_KEY = "cfgcgvui78tytr67rfyvfrvftytyiumjkhsgnhmjhnmjmbnbjbhnkhbnvhbnvmnm"

func GenerateToken(rollno string) (signedToken string, err error) {
	claims := &SignedDetails{
		RollNo: rollno,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(),
		},
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(SECRET_KEY))

	if err != nil {
		log.Panic(err)
		return
	}

	return token, err
}

func ValidateToken(signedToken string) (claims *SignedDetails, msg string) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&SignedDetails{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SECRET_KEY), nil
		},
	)

	if err != nil {
		msg = err.Error()
		return
	}

	claims, ok := token.Claims.(*SignedDetails)
	if !ok {
		msg = "the token is invalid"
		msg = err.Error()
		return
	}

	if claims.ExpiresAt < time.Now().Local().Unix() {
		msg = "token is expired"
		msg = err.Error()
		return
	}
	return claims, msg
}

// func (setup *OrgSetup) AddStudent(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println("Received Invoke request")
// 	if err := r.ParseForm(); err != nil {
// 		fmt.Fprintf(w, "ParseForm() err: %s", err)
// 		return
// 	}

// 	chainCodeName := "basic"
// 	channelID := "mychannel"
// 	function := "AddStudent"
// 	args := r.Form["args"]
// 	for _, value := range args {
// 		fmt.Println(value)
// 	}

// 	cryptokey, err := uuid.NewV7()
// 	if err != nil {
// 		fmt.Fprintf(w, "Error cryptokey  %s", err)
// 		return
// 	}

// 	dateTime := TodayDateTime()
// 	newcryptokey := "co" + dateTime + "_" + cryptokey.String()
// 	additionalArgs := []string{newcryptokey}
// 	combinedArgs := append(additionalArgs, args...)

//		fmt.Printf("channel: %s, chaincode: %s, function: %s, args: %s\n", channelID, chainCodeName, function, combinedArgs)
//		network := setup.Gateway.GetNetwork(channelID)
//		contract := network.GetContract(chainCodeName)
//		w.Header().Set("Content-Type", "application/json")
//		txn_proposal, err := contract.NewProposal(function, client.WithArguments(combinedArgs...))
//		if err != nil {
//			http.Error(w, "Error", http.StatusInternalServerError)
//			fmt.Printf("Error creating txn proposal: %s", err)
//			return
//		}
//		txn_endorsed, err := txn_proposal.Endorse()
//		if err != nil {
//			http.Error(w, "Error", http.StatusInternalServerError)
//			fmt.Printf("Error endorsing txn: %s", err)
//			return
//		}
//		txn_committed, err := txn_endorsed.Submit()
//		if err != nil {
//			http.Error(w, "Error", http.StatusInternalServerError)
//			fmt.Printf("Error submitting transaction: %s", err)
//			return
//		}
//		fmt.Println(txn_committed.TransactionID())
//		//fmt.Fprintf(w, "%s", txn_committed.TransactionID())
//		w.WriteHeader(http.StatusOK)
//		fmt.Fprintf(w, "%s", txn_endorsed.Result())
//	}
func (setup *OrgSetup) AddStudent(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received Invoke request")
	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %s", err)
		return
	}

	chainCodeName := "basic"
	channelID := "mychannel"
	function := "AddStudent"
	args := r.Form["args"]
	var password string = args[len(args)-2]
	var hashPassword string = HashPassword(password)

	args[len(args)-2] = hashPassword
	for _, value := range args {
		fmt.Println(value)
	}

	cryptokey, err := uuid.NewV7()
	if err != nil {
		fmt.Fprintf(w, "Error cryptokey %s", err)
		return
	}
	dateTime := TodayDateTime()
	newcryptokey := "co" + dateTime + "_" + cryptokey.String()
	additionalArgs := []string{newcryptokey}
	combinedArgs := append(additionalArgs, args...)

	fmt.Printf("channel: %s, chaincode: %s, function: %s, args: %s\n", channelID, chainCodeName, function, combinedArgs)
	network := setup.Gateway.GetNetwork(channelID)
	contract := network.GetContract(chainCodeName)
	w.Header().Set("Content-Type", "application/json")

	txn_proposal, err := contract.NewProposal(function, client.WithArguments(combinedArgs...))
	if err != nil {
		http.Error(w, "Error", http.StatusInternalServerError)
		fmt.Printf("Error creating txn proposal: %s", err)
		return
	}

	txn_endorsed, err := txn_proposal.Endorse()
	if err != nil {
		// Check if the error is due to a user already existing
		if strings.Contains(err.Error(), "user with rollNo") {

			http.Error(w, "User already exists", http.StatusConflict)
			fmt.Printf("User already exists: %s", err)
			return
		}
		http.Error(w, "Error", http.StatusInternalServerError)
		fmt.Printf("Error endorsing txn: %s", err)
		return
	}

	txn_committed, err := txn_endorsed.Submit()
	if err != nil {
		http.Error(w, "Error", http.StatusInternalServerError)
		fmt.Printf("Error submitting transaction: %s", err)
		return
	}

	fmt.Println(txn_committed.TransactionID())
	w.WriteHeader(http.StatusOK)

	token, err := GenerateToken(args[2])
	if err != nil {
		http.Error(w, "Error", http.StatusInternalServerError)
		fmt.Printf("Registered, Failed to generate token %s", err)
		return
	}

	var tokenmap map[string]string = make(map[string]string)
	tokenmap["jwttoken"] = token

	tokenjson, err := json.Marshal(tokenmap)

	if err != nil {
		http.Error(w, "Error", http.StatusInternalServerError)
		fmt.Printf("Registered, Failed to marshal token %s", err)
		return
	}

	fmt.Fprintf(w, "%s", tokenjson)
}

func (setup *OrgSetup) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received Update Password request")

	// clientToken := r.Header.Get("jwttoken")
	// if clientToken == "" {
	// 	w.WriteHeader(http.StatusUnauthorized)
	// 	fmt.Fprintf(w, "No authorization header provided")
	// 	return
	// }

	// _, err1 := ValidateToken(clientToken)
	// if err1 != "" {
	// 	w.WriteHeader(http.StatusUnauthorized)
	// 	fmt.Fprintf(w, "Invalid authorization header provided")
	// 	return
	// }

	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %s", err)
		return
	}

	chainCodeName := "basic"
	channelID := "mychannel"
	function := "UpdatePassword"
	RollNo := r.FormValue("RollNo")
	newPassword := r.FormValue("newPassword")
	var hashPassword string = HashPassword(newPassword)
	args := []string{RollNo, hashPassword}

	fmt.Printf("channel: %s, chaincode: %s, function: %s, args: %s\n", channelID, chainCodeName, function, args)
	network := setup.Gateway.GetNetwork(channelID)
	contract := network.GetContract(chainCodeName)
	w.Header().Set("Content-Type", "application/json")

	txn_proposal, err := contract.NewProposal(function, client.WithArguments(args...))
	if err != nil {
		http.Error(w, "Error", http.StatusInternalServerError)
		fmt.Printf("Error creating txn proposal: %s", err)
		return
	}

	txn_endorsed, err := txn_proposal.Endorse()
	if err != nil {
		http.Error(w, "Error", http.StatusInternalServerError)
		fmt.Printf("Error endorsing txn: %s", err)
		return
	}

	txn_committed, err := txn_endorsed.Submit()
	if err != nil {
		if strings.Contains(err.Error(), "failed to") {
			http.Error(w, "Student is not registered.", http.StatusUnauthorized)
			fmt.Printf("Invalid credentials: %s", err)
			return
		}
		// http.Error(w, "Error", http.StatusInternalServerError)
		// fmt.Printf("Error submitting transaction: %s", err)
		return
	}
	fmt.Println(txn_committed.TransactionID())
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Password updated successfully")
}

func (setup *OrgSetup) LogIn(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received Login request")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		fmt.Printf("ParseForm() err: %s", err)
		return
	}

	chainCodeName := "basic"
	channelID := "mychannel"
	function := "LogIn"
	RollNo := r.FormValue("RollNo")
	Password := r.FormValue("Password")
	args := []string{RollNo, Password}

	fmt.Printf("channel: %s, chaincode: %s, function: %s, args: %s\n", channelID, chainCodeName, function, args)
	network := setup.Gateway.GetNetwork(channelID)
	contract := network.GetContract(chainCodeName)
	w.Header().Set("Content-Type", "application/json")

	result, err := contract.Evaluate(function, client.WithArguments(args...))
	if err != nil {
		// Check if the error is related to invalid RollNo or Password
		if strings.Contains(err.Error(), "invalid RollNo or Password") {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			fmt.Printf("Invalid credentials: %s", err)
			return
		}
		http.Error(w, "Error evaluating transaction", http.StatusInternalServerError)
		fmt.Printf("Error evaluating transaction: %s", err)
		return
	}

	statusCode, err := strconv.Atoi(string(result))
	if err != nil {
		http.Error(w, "Error parsing status code", http.StatusInternalServerError)
		fmt.Printf("Error parsing status code: %s", err)
		return
	}

	switch statusCode {
	case loginSuccess:
		token, err := GenerateToken(args[0])
		if err != nil {
			http.Error(w, "Error", http.StatusInternalServerError)
			fmt.Printf("Registered, Failed to generate token %s", err)
			return
		}

		var tokenmap map[string]string = make(map[string]string)
		tokenmap["jwttoken"] = token

		tokenjson, err := json.Marshal(tokenmap)

		if err != nil {
			http.Error(w, "Error", http.StatusInternalServerError)
			fmt.Printf("Registered, Failed to marshal token %s", err)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "%s", tokenjson)
	case loginFailedInvalidCredentials:
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	case loginFailedInternalError:
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	default:
		http.Error(w, "Unknown error", http.StatusInternalServerError)
	}
}
