package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func (setup OrgSetup) CheckStudent(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received Query request")
	//queryParams := r.URL.Query()
	//chainCodeName := queryParams.Get("chaincodeid")
	chainCodeName := "basic"
	channelID := "mychannel"
	function := "CheckStudent"
	args := r.URL.Query()["ID"]
	fmt.Printf("channel: %s, chaincode: %s, function: %s, args: %s\n", channelID, chainCodeName, function, args)
	network := setup.Gateway.GetNetwork(channelID)
	contract := network.GetContract(chainCodeName)
	w.Header().Set("Content-Type", "application/json")
	evaluateResponse, err := contract.EvaluateTransaction(function, args...)
	if err != nil {
		fmt.Fprintf(w, "%s", err)
		return
	}
	fmt.Fprintf(w, "%s", evaluateResponse)
}

// func (setup OrgSetup) LogIn(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println("Received Query request")
// 	//queryParams := r.URL.Query()
// 	//chainCodeName := queryParams.Get("chaincodeid")
// 	chainCodeName := "basic"
// 	channelID := "mychannel"
// 	function := "LogIn"
// 	args := r.URL.Query()["ID"]
// 	fmt.Printf("channel: %s, chaincode: %s, function: %s, args: %s\n", channelID, chainCodeName, function, args)
// 	network := setup.Gateway.GetNetwork(channelID)
// 	contract := network.GetContract(chainCodeName)
// 	w.Header().Set("Content-Type", "application/json")
// 	evaluateResponse, err := contract.EvaluateTransaction(function, args...)
// 	if err != nil {
// 		http.Error(w, "Invalid Credentials", http.StatusInternalServerError)
// 		fmt.Printf("Error submitting transaction: %s", err)
// 		//fmt.Fprintf(w, "%s", err)
// 		return
// 	}
// 	fmt.Fprintf(w, "%s", evaluateResponse)
// }

type Student struct {
	RollNo       string `json:"rollno"`
	Name         string `json:"name"`
	Department   string `json:"department"`
	Email        string `json:"email"`
	CryptoKey    string `json:"cryptokey"`
	Password     string `json:"password"`
	MobileNumber string `json:"mobilenumber"`
}

type StudentDetailsReturnStruct struct {
	RollNo       string `json:"rollno"`
	Name         string `json:"name"`
	Department   string `json:"department"`
	Email        string `json:"email"`
	CryptoKey    string `json:"cryptokey"`
	MobileNumber string `json:"mobilenumber"`
}

func (setup OrgSetup) GetStudentDetails(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received Query request")
	//queryParams := r.URL.Query()
	//chainCodeName := queryParams.Get("chaincodeid")

	clientToken := r.Header.Get("jwttoken")
	if clientToken == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "No authorization header provided")
		return
	}

	_, err1 := ValidateToken(clientToken)
	if err1 != "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Invalid authorization header provided")
		return
	}

	chainCodeName := "basic"
	channelID := "mychannel"
	function := "GetStudentDetails"
	args := r.URL.Query()["RollNo"]
	fmt.Printf("channel: %s, chaincode: %s, function: %s, args: %s\n", channelID, chainCodeName, function, args)
	network := setup.Gateway.GetNetwork(channelID)
	contract := network.GetContract(chainCodeName)
	w.Header().Set("Content-Type", "application/json")
	evaluateResponse, err := contract.EvaluateTransaction(function, args...)
	if err != nil {
		if strings.Contains(err.Error(), "failed to check if student is registered") {
			http.Error(w, "Student is not registered", http.StatusUnauthorized)
			fmt.Printf("Invalid credentials: %s", err)
			return
		}
		http.Error(w, "Error evaluating transaction", http.StatusInternalServerError)
		fmt.Printf("Error evaluating transaction: %s", err)
		fmt.Fprintf(w, "%s", err)
		return
	}

	var student Student
	if err = json.Unmarshal(evaluateResponse, &student); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error in unmarshal")
		return
	}

	var retStudent StudentDetailsReturnStruct
	retStudent.RollNo = student.RollNo
	retStudent.Name = student.Name
	retStudent.Department = student.Department
	retStudent.Email = student.Email
	retStudent.CryptoKey = student.CryptoKey
	retStudent.MobileNumber = student.MobileNumber

	retStudentJson, err := json.Marshal(retStudent)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error in marshal")
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", retStudentJson)
}

func (setup OrgSetup) IsStudentRegister(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received Query request")
	//queryParams := r.URL.Query()
	//chainCodeName := queryParams.Get("chaincodeid")
	chainCodeName := "basic"
	channelID := "mychannel"
	function := "IsStudentRegister"
	args := r.URL.Query()["RollNo"]
	fmt.Printf("channel: %s, chaincode: %s, function: %s, args: %s\n", channelID, chainCodeName, function, args)
	network := setup.Gateway.GetNetwork(channelID)
	contract := network.GetContract(chainCodeName)
	w.Header().Set("Content-Type", "application/json")
	evaluateResponse, err := contract.EvaluateTransaction(function, args...)
	if err != nil {

		fmt.Fprintf(w, "%s", err)
		return
	}
	fmt.Fprintf(w, "%s", evaluateResponse)
}

// func (setup *OrgSetup) LogIn(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println("Received Login request")
// 	if err := r.ParseForm(); err != nil {
// 		http.Error(w, "Error parsing form data", http.StatusBadRequest)
// 		fmt.Printf("ParseForm() err: %s", err)
// 		return
// 	}

// 	chainCodeName := "basic"
// 	channelID := "mychannel"
// 	function := "LogIn"
// 	RollNo := r.FormValue("RollNo")
// 	Password := r.FormValue("Password")
// 	args := []string{RollNo, Password}

// 	fmt.Printf("channel: %s, chaincode: %s, function: %s, args: %s\n", channelID, chainCodeName, function, args)
// 	network := setup.Gateway.GetNetwork(channelID)
// 	contract := network.GetContract(chainCodeName)
// 	w.Header().Set("Content-Type", "application/json")

// 	result, err := contract.Evaluate(function, client.WithArguments(args...))
// 	if err != nil {
// 		// Check if the error is related to invalid RollNo or Password
// 		if strings.Contains(err.Error(), "invalid RollNo or Password") {
// 			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
// 			fmt.Printf("Invalid credentials: %s", err)
// 			return
// 		}
// 		http.Error(w, "Error evaluating transaction", http.StatusInternalServerError)
// 		fmt.Printf("Error evaluating transaction: %s", err)
// 		return
// 	}

// 	statusCode, err := strconv.Atoi(string(result))
// 	if err != nil {
// 		http.Error(w, "Error parsing status code", http.StatusInternalServerError)
// 		fmt.Printf("Error parsing status code: %s", err)
// 		return
// 	}

// 	switch statusCode {
// 	case loginSuccess:
// 		w.WriteHeader(http.StatusOK)
// 		fmt.Fprintf(w, "Login successful")
// 	case loginFailedInvalidCredentials:
// 		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
// 	case loginFailedInternalError:
// 		http.Error(w, "Internal server error", http.StatusInternalServerError)
// 	default:
// 		http.Error(w, "Unknown error", http.StatusInternalServerError)
// 	}
// }
