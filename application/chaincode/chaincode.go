package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"golang.org/x/crypto/bcrypt"
)

const (
	loginSuccess                  = 200
	loginFailedInvalidCredentials = 401
	loginFailedInternalError      = 500
)

// Define the Student struct
type Student struct {
	RollNo     string `json:"rollno"`
	Name       string `json:"name"`
	Department string `json:"department"`
	Email      string `json:"email"`
	// YearOfStudy string `json:"yearOfStudy"`
	CryptoKey    string `json:"cryptokey"`
	Password     string `json:"password"`
	MobileNumber string `json:"mobilenumber"`
}

type CryptoKeyUser struct {
	RollNo    string `json:"rollno"`
	CryptoKey string `json:"cryptokey"`
}

// Define the SmartContract structure
type SmartContract struct {
	contractapi.Contract
}

func VerifyPassword(userPassword string, providedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	if err != nil {
		check = false
	}
	return check
}

func (s *SmartContract) GetStudentDetails(ctx contractapi.TransactionContextInterface, RollNo string) (*Student, error) {
	student, err := s.CheckStudent(ctx, RollNo)
	if err != nil {
		return nil, fmt.Errorf("failed to get student details: %w", err)
	}
	if student == nil {
		return nil, fmt.Errorf("student with RollNo %s does not exist", RollNo)
	}
	return student, nil
}

// AddStudent adds a new student to the ledger
func (s *SmartContract) AddStudent(ctx contractapi.TransactionContextInterface, CryptoKey string, Name string, Email string, RollNo string, Department string, Password string, MobileNumber string) error {
	existingStudent, err := s.CheckStudent(ctx, RollNo)
	if err == nil && existingStudent != nil {
		return fmt.Errorf("user with rollNo %s already exists", RollNo)
	}

	// hashedPassword, err := s.hashPassword(Password)
	// if err != nil {
	// 	return err
	// }

	Student := Student{
		CryptoKey:    CryptoKey,
		Name:         Name,
		Email:        Email,
		RollNo:       RollNo,
		Department:   Department,
		Password:     Password,
		MobileNumber: MobileNumber,
	}

	CryptoKeyUser := CryptoKeyUser{
		RollNo:    RollNo,
		CryptoKey: CryptoKey,
	}

	fmt.Println(CryptoKey)

	StudentJson, err := json.Marshal(Student)
	if err != nil {
		return fmt.Errorf("failed to marshal student data: %w", err)
	}

	CryptoKeyJson, err := json.Marshal(CryptoKeyUser)
	if err != nil {
		return fmt.Errorf("failed to marshal crypto key data: %w", err)
	}

	err = ctx.GetStub().PutState(RollNo, CryptoKeyJson)

	if err != nil {
		return fmt.Errorf("failed to put state: %v", err)
	}

	return ctx.GetStub().PutState(CryptoKey, StudentJson)
}

func (s *SmartContract) CheckStudent(ctx contractapi.TransactionContextInterface, RollNo string) (*Student, error) {
	// First, get the CryptoKeyUser struct using the RollNo
	cryptoKeyUser, err := s.IsStudentRegister(ctx, RollNo)
	if err != nil {
		return nil, fmt.Errorf("failed to check if student is registered: %w", err)
	}
	if cryptoKeyUser == nil {
		return nil, fmt.Errorf("student with RollNo %s does not exist", RollNo)
	}

	// Use the CryptoKey to get the student's details
	studentJson, err := ctx.GetStub().GetState(cryptoKeyUser.CryptoKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read student details from ledger: %w", err)
	}
	if studentJson == nil {
		return nil, fmt.Errorf("student details not found for RollNo %s", RollNo)
	}

	var student Student
	err = json.Unmarshal(studentJson, &student)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal student details: %w", err)
	}

	return &student, nil
}

func (s *SmartContract) LogIn(ctx contractapi.TransactionContextInterface, RollNo string, Password string) (int, error) {
	cryptoKeyUser, err := s.IsStudentRegister(ctx, RollNo)
	if err != nil {
		return loginFailedInvalidCredentials, fmt.Errorf("failed to check if student is registered: %w", err)
	}
	if cryptoKeyUser == nil {
		return loginFailedInvalidCredentials, fmt.Errorf("student with RollNo %s does not exist", RollNo)
	}

	studentJson, err := ctx.GetStub().GetState(cryptoKeyUser.CryptoKey)
	if err != nil {
		return loginFailedInternalError, fmt.Errorf("failed to read student details from ledger: %w", err)
	}
	if studentJson == nil {
		return loginFailedInternalError, fmt.Errorf("student details not found for RollNo %s", RollNo)
	}

	var student Student
	err = json.Unmarshal(studentJson, &student)
	if err != nil {
		return loginFailedInvalidCredentials, fmt.Errorf("failed to unmarshal student details: %w", err)
	}
	if student.RollNo == RollNo && VerifyPassword(Password, student.Password) {
		return loginSuccess, nil
	}
	return loginFailedInvalidCredentials, fmt.Errorf("invalid RollNo or Password")
}

func (s *SmartContract) IsStudentRegister(ctx contractapi.TransactionContextInterface, RollNo string) (*CryptoKeyUser, error) {
	cryptoKeyJson, err := ctx.GetStub().GetState(RollNo)

	if err != nil {
		return nil, fmt.Errorf("failed to read user from ledger: %w", err)
	}

	if cryptoKeyJson == nil {
		return nil, fmt.Errorf("fails")
	}

	var cryptokeyuser CryptoKeyUser
	err = json.Unmarshal(cryptoKeyJson, &cryptokeyuser)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal CryptoKeyUser: %w", err)
	}
	return &cryptokeyuser, nil
}
func (s *SmartContract) UpdatePassword(ctx contractapi.TransactionContextInterface, RollNo string, newPassword string) error {
	// Retrieve the student's current details
	cryptoKeyUser, err := s.IsStudentRegister(ctx, RollNo)
	if err != nil {
		return fmt.Errorf("failed to check if student is registered: %w", err)
	}
	if cryptoKeyUser == nil {
		return fmt.Errorf("student with RollNo %s does not exist", RollNo)
	}

	// Use the CryptoKey to get the student's details
	studentJson, err := ctx.GetStub().GetState(cryptoKeyUser.CryptoKey)
	if err != nil {
		return fmt.Errorf("failed to read student details from ledger: %w", err)
	}
	if studentJson == nil {
		return fmt.Errorf("failed to find student details sfor RollNo %s", RollNo)
	}

	var student Student
	err = json.Unmarshal(studentJson, &student)
	if err != nil {
		return fmt.Errorf("failed to unmarshal student details: %w", err)
	}

	// Update the student's password with the hashed password
	student.Password = newPassword

	// Save the updated student details back to the ledger
	updatedStudentJson, err := json.Marshal(student)
	if err != nil {
		return fmt.Errorf("failed to marshal updated student details: %w", err)
	}

	err = ctx.GetStub().PutState(cryptoKeyUser.CryptoKey, updatedStudentJson)
	if err != nil {
		return fmt.Errorf("failed to update student password in ledger: %w", err)
	}
	return nil
}
func main() {
	chaincode, err := contractapi.NewChaincode(new(SmartContract))
	if err != nil {
		fmt.Printf("Error creating chaincode: %s", err.Error())
		return
	}
	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting chaincode: %s", err.Error())
	}
}
