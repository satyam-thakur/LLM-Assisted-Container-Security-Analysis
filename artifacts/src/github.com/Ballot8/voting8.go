package main

import (
    "crypto/sha1"
    "encoding/json"
    "fmt"

    "github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// VotingContract provides functions for managing voting on mychannel
type VotingContract struct {
    contractapi.Contract
}

// BallotRecord represents the structure for storing ballot information on mychannel
type BallotRecord struct {
    Ballot          string `json:"ballot"`
    VotingTokenHash string `json:"votingTokenHash"`
    ID              string `json:"id"`
}

// VotingTokenRecord represents the structure for storing voting token information on mychannel1
type VotingTokenRecord struct {
    VcmsTokenHash   string `json:"vcmsTokenHash"`
    ID              string `json:"id"`
    Salt            string `json:"salt"`
    VCMSdSignature  string `json:"vcmsdSignature"`
}

// TransactionType1 represents a transaction structure for type1 transactions
type TransactionType1 struct {
    VcmsTokenHash   string `json:"vcmsTokenHash"`
    ID              string `json:"id"`
    VCMSdSignature  string `json:"vcmsdSignature"`
}

// PostVotingRecord represents the structure for post-voting information
type PostVotingRecord struct {
    HashedVcmsToken string `json:"hashedVcmsToken"`
    VotingToken     string `json:"votingToken"`
    ID              string `json:"id"`
}

// QueryCastVoteResponse represents the response structure for QueryCastVote
type QueryCastVoteResponse struct {
    VotingTokenHash   string            `json:"votingTokenHash"`
    HashedVotingToken string            `json:"hashedVotingToken"`
    Status            bool              `json:"status"`
    TransactionType1  *TransactionType1 `json:"transactionType1,omitempty"`
    Ballot            *BallotRecord     `json:"ballot,omitempty"`
}

// QueryPostVotingResponse represents the response structure for QueryPostVoting
type QueryPostVotingResponse struct {
    VotingTokenHash string            `json:"votingTokenHash"`
    HashedVcmsToken string            `json:"hashedVcmsToken"`
    Status          bool              `json:"status"`
    PostVoting      *PostVotingRecord `json:"postVoting,omitempty"`
}

// CastVote takes voter input and processes it
func (c *VotingContract) CastVote(ctx contractapi.TransactionContextInterface, ballot string, votingTokenhash string) error {
    votingTokenRecord, err := c.GetVotingTokenFromChannel2(ctx, votingTokenhash)
    if err != nil {
        return fmt.Errorf("failed to verify voting token: %v", err)
    }

    Index1 := "00" + votingTokenRecord.ID
    Index2 := "01" + votingTokenRecord.ID

    exists, err := c.idExistsInChannel1(ctx, Index2)
    if err != nil {
        return err
    }
    if exists {
        return fmt.Errorf("a vote with ID %s has already been cast", Index2)
    }

    hashedVotingToken := c.hashWithSalt(votingTokenhash, votingTokenRecord.Salt)

    ballotRecord := BallotRecord{
        Ballot:          ballot,
        VotingTokenHash: hashedVotingToken,
        ID:              Index2,
    }

    ballotJSON, err := json.Marshal(ballotRecord)
    if err != nil {
        return fmt.Errorf("failed to marshal ballot record: %v", err)
    }

    err = ctx.GetStub().PutState(Index2, ballotJSON)
    if err != nil {
        return fmt.Errorf("failed to store ballot: %v", err)
    }

    transactionType1 := TransactionType1{
        VcmsTokenHash:  hashedVotingToken,
        ID:             Index1,
        VCMSdSignature: votingTokenRecord.VCMSdSignature,
    }

    transactionJSON, err := json.Marshal(transactionType1)
    if err != nil {
        return fmt.Errorf("failed to marshal transaction type1 record: %v", err)
    }

    err = ctx.GetStub().PutState(Index1, transactionJSON)
    if err != nil {
        return fmt.Errorf("failed to store transaction type1 record: %v", err)
    }

    return nil
}

// PostVoting handles post-voting token input and appends it to the blockchain
func (c *VotingContract) PostVoting(ctx contractapi.TransactionContextInterface, votingTokenHash string, votingToken string) error {
    votingTokenRecord, err := c.GetVotingTokenFromChannel2(ctx, votingTokenHash)
    if err != nil {
        return fmt.Errorf("failed to verify voting token from channel1: %v", err)
    }

    Index3 := "10" + votingTokenRecord.ID

    exists, err := c.idExistsInChannel1(ctx, Index3)
    if err != nil {
        return err
    }
    if exists {
        return fmt.Errorf("a VCMS hash token record with ID %s already exists", Index3)
    }

    hashedVcmsToken := c.hashWithSalt(votingTokenRecord.VcmsTokenHash, votingTokenRecord.Salt)

    postVotingRecord := PostVotingRecord{
        HashedVcmsToken: hashedVcmsToken,
        VotingToken:     votingToken,
        ID:              Index3,
    }

    postVotingJSON, err := json.Marshal(postVotingRecord)
    if err != nil {
        return fmt.Errorf("failed to marshal post-voting record: %v", err)
    }

    err = ctx.GetStub().PutState(Index3, postVotingJSON)
    if err != nil {
        return fmt.Errorf("failed to store post-voting record: %v", err)
    }

    return nil
}

// QueryCastVote queries if a CastVote transaction has been committed using the votingTokenHash
func (c *VotingContract) QueryCastVote(ctx contractapi.TransactionContextInterface, votingTokenHash string) (*QueryCastVoteResponse, error) {
    votingTokenRecord, err := c.GetVotingTokenFromChannel2(ctx, votingTokenHash)
    if err != nil {
        return nil, fmt.Errorf("failed to retrieve voting token: %v", err)
    }

    hashedVotingToken := c.hashWithSalt(votingTokenHash, votingTokenRecord.Salt)
    userID := votingTokenRecord.ID
    transactionType1ID := "00" + userID
    ballotID := "01" + userID

    result := &QueryCastVoteResponse{
        VotingTokenHash:   votingTokenHash,
        HashedVotingToken: hashedVotingToken,
        Status:            false,
    }

    // Check for TransactionType1 record
    transactionJSON, err := ctx.GetStub().GetState(transactionType1ID)
    if err == nil && transactionJSON != nil {
        var tx TransactionType1
        if json.Unmarshal(transactionJSON, &tx) == nil {
            if tx.VcmsTokenHash == hashedVotingToken {
                result.TransactionType1 = &tx
                result.Status = true
            }
        }
    }

    // Check for Ballot record
    ballotJSON, err := ctx.GetStub().GetState(ballotID)
    if err == nil && ballotJSON != nil {
        var ballot BallotRecord
        if json.Unmarshal(ballotJSON, &ballot) == nil {
            if ballot.VotingTokenHash == hashedVotingToken {
                result.Ballot = &ballot
                result.Status = true
            }
        }
    }

    if !result.Status {
        return nil, fmt.Errorf("no CastVote transactions found for votingTokenHash %s", votingTokenHash)
    }

    return result, nil
}

// QueryPostVoting queries if a PostVoting transaction has been committed using the votingTokenHash
func (c *VotingContract) QueryPostVoting(ctx contractapi.TransactionContextInterface, votingTokenHash string) (*QueryPostVotingResponse, error) {
    votingTokenRecord, err := c.GetVotingTokenFromChannel2(ctx, votingTokenHash)
    if err != nil {
        return nil, fmt.Errorf("failed to retrieve voting token: %v", err)
    }

    hashedVcmsToken := c.hashWithSalt(votingTokenRecord.VcmsTokenHash, votingTokenRecord.Salt)
    userID := votingTokenRecord.ID
    postVotingID := "10" + userID

    result := &QueryPostVotingResponse{
        VotingTokenHash: votingTokenHash,
        HashedVcmsToken: hashedVcmsToken,
        Status:          false,
    }

    postVotingJSON, err := ctx.GetStub().GetState(postVotingID)
    if err != nil || postVotingJSON == nil {
        return nil, fmt.Errorf("no PostVoting transactions found for votingTokenHash %s", votingTokenHash)
    }

    var postVoting PostVotingRecord
    err = json.Unmarshal(postVotingJSON, &postVoting)
    if err != nil {
        return nil, fmt.Errorf("failed to unmarshal post voting record: %v", err)
    }

    if postVoting.HashedVcmsToken == hashedVcmsToken {
        result.PostVoting = &postVoting
        result.Status = true
        return result, nil
    }

    return nil, fmt.Errorf("no matching PostVoting transactions found for votingTokenHash %s", votingTokenHash)
}

// hashWithSalt computes SHA-256 hash of a given input concatenated with salt
func (c *VotingContract) hashWithSalt(input string, salt string) string {
    data := input + salt
    hash := sha1.Sum([]byte(data))
    return fmt.Sprintf("%x", hash[:])
}

// GetVotingTokenFromChannel2 retrieves and verifies the voting token from channel2
func (c *VotingContract) GetVotingTokenFromChannel2(ctx contractapi.TransactionContextInterface, votingTokenhash string) (*VotingTokenRecord, error) {
    channel2Stub := ctx.GetStub().InvokeChaincode("voting6", [][]byte{
        []byte("GetVotingTokenRecord"),
        []byte(votingTokenhash),
    }, "mychannel1")

    if channel2Stub.Status != 200 {
        return nil, fmt.Errorf("failed to retrieve voting token from channel2: %s", channel2Stub.Message)
    }

    var record VotingTokenRecord
    err := json.Unmarshal(channel2Stub.Payload, &record)
    if err != nil {
        return nil, fmt.Errorf("failed to unmarshal voting token record: %v", err)
    }

    return &record, nil
}

// idExistsInChannel1 checks if an ID already exists in channel1
func (c *VotingContract) idExistsInChannel1(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
    ballotJSON, err := ctx.GetStub().GetState(id)
    if err != nil {
        return false, fmt.Errorf("failed to read from world state: %v", err)
    }
    return ballotJSON != nil, nil
}

func main() {
    chaincode, err := contractapi.NewChaincode(&VotingContract{})
    if err != nil {
        fmt.Printf("Error creating voting chaincode: %v", err)
        return
    }

    if err := chaincode.Start(); err != nil {
        fmt.Printf("Error starting voting chaincode: %v", err)
    }
}
