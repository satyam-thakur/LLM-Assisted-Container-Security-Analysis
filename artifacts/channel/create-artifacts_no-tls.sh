#!/bin/bash

# chmod -R 0755 ./crypto-config
# Delete existing artifacts
# rm -rf ./crypto-config
rm genesis.block mychannel.tx mychannel1.tx *.tx
rm -rf ../../channel-artifacts/*

#Generate Crypto artifactes for organizations
# cryptogen generate --config=./crypto-config.yaml --output=./crypto-config/

# System channel
SYS_CHANNEL="sys-channel"

# Generate System Genesis block
configtxgen -profile OrdererGenesis -configPath ./ -channelID $SYS_CHANNEL  -outputBlock ./genesis.block

export CHANNEL_NAME="mychannel"
echo $CHANNEL_NAME

# Generate channel configuration block
configtxgen -profile BasicChannel -configPath ./ -outputCreateChannelTx ./mychannel.tx -channelID $CHANNEL_NAME

echo "#######    Generating anchor peer update for Org1MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org1MSPanchors.tx -channelID $CHANNEL_NAME -asOrg Org1MSP

echo "#######    Generating anchor peer update for Org2MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org2MSPanchors.tx -channelID $CHANNEL_NAME -asOrg Org2MSP

echo "######    Generating anchor peer update for Org3MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org3MSPanchors.tx -channelID $CHANNEL_NAME -asOrg Org3MSP

echo "#######    Generating anchor peer update for Org4MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org4MSPanchors.tx -channelID $CHANNEL_NAME -asOrg Org4MSP

echo "#######    Generating anchor peer update for Org5MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org5MSPanchors.tx -channelID $CHANNEL_NAME -asOrg Org5MSP

echo "#######    Generating anchor peer update for Org6MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org6MSPanchors.tx -channelID $CHANNEL_NAME -asOrg Org6MSP

echo "#######    Generating anchor peer update for Org7MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org7MSPanchors.tx -channelID $CHANNEL_NAME -asOrg Org7MSP

echo "#######    Generating anchor peer update for Org8MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org8MSPanchors.tx -channelID $CHANNEL_NAME -asOrg Org8MSP

echo "#######    Generating anchor peer update for Org9MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org9MSPanchors.tx -channelID $CHANNEL_NAME -asOrg Org9MSP

echo "#######    Generating anchor peer update for Org10MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org10MSPanchors.tx -channelID $CHANNEL_NAME -asOrg Org10MSP

export CHANNEL_NAME="mychannel1"
echo $CHANNEL_NAME

Generate channel configuration block
configtxgen -profile BasicChannel -configPath ./ -outputCreateChannelTx ./mychannel1.tx -channelID $CHANNEL_NAME

echo "#######    Generating anchor peer update for Org1MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org1MSPanchors1.tx -channelID $CHANNEL_NAME -asOrg Org1MSP

echo "#######    Generating anchor peer update for Org2MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org2MSPanchors1.tx -channelID $CHANNEL_NAME -asOrg Org2MSP

echo "######    Generating anchor peer update for Org3MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org3MSPanchors1.tx -channelID $CHANNEL_NAME -asOrg Org3MSP

echo "#######    Generating anchor peer update for Org4MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org4MSPanchors1.tx -channelID $CHANNEL_NAME -asOrg Org4MSP

echo "#######    Generating anchor peer update for Org5MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org5MSPanchors1.tx -channelID $CHANNEL_NAME -asOrg Org5MSP

echo "#######    Generating anchor peer update for Org6MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org6MSPanchors1.tx -channelID $CHANNEL_NAME -asOrg Org6MSP

echo "#######    Generating anchor peer update for Org7MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org7MSPanchors1.tx -channelID $CHANNEL_NAME -asOrg Org7MSP

echo "#######    Generating anchor peer update for Org8MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org8MSPanchors1.tx -channelID $CHANNEL_NAME -asOrg Org8MSP

echo "#######    Generating anchor peer update for Org9MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org9MSPanchors1.tx -channelID $CHANNEL_NAME -asOrg Org9MSP

echo "#######    Generating anchor peer update for Org10MSP  ##########"
configtxgen -profile BasicChannel -configPath ./ -outputAnchorPeersUpdate ./Org10MSPanchors1.tx -channelID $CHANNEL_NAME -asOrg Org10MSP

echo "artifacts created successfully"