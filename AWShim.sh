#!/bin/bash
# Author: Justin Kikani 
# Last Modified: 03/24/2022
# Version: 1.0.0
# Release Notes: Initial Release!
# Purpose: To simplify and standardize the creation of the resources, 
# permissions, and policies needed to be able to create a Cloud Connector
# within the Blumira platform.
# Notice: We/I am not responsible for additional cloud costs incurred due to this script.

# To run this script please go to your AWS management console and run git clone git clone https://github.com/Blumira/AWShim.
# CD into the directory.
# Use chmod +X to make this script executable and then run this script.
# Longform TODO: Add in cleanup option to remove created resources/policies

printf ' ______  __      __  __  __    __  __  ______  ______    
/\  == \/\ \    /\ \/\ \/\ "-./  \/\ \/\  == \/\  __ \   
\ \  __<\ \ \___\ \ \_\ \ \ \-./\ \ \ \ \  __<\ \  __ \  
 \ \_____\ \_____\ \_____\ \_\ \ \_\ \_\ \_\ \_\ \_\ \_\ 
  \/_____/\/_____/\/_____/\/_/  \/_/\/_/\/_/ /_/\/_/\/_/ 
                                                         
 ______  __     __  ______  __  __  __  __    __         
/\  __ \/\ \  _ \ \/\  ___\/\ \_\ \/\ \/\ "-./  \        
\ \  __ \ \ \/ ".\ \ \___  \ \  __ \ \ \ \ \-./\ \       
 \ \_\ \_\ \__/".~\_\/\_____\ \_\ \_\ \_\ \_\ \ \_\      
  \/_/\/_/\/_/   \/_/\/_____/\/_/\/_/\/_/\/_/  \/_/      
                                                         '
printf "\n"

# Output Date/Time for Start
startDateTime=$(date)

# Standardized Blumira Kinesis Data Stream name
kStreamPrefix="blumirastream"

# Script Preamble
echo 'Welcome to AWShim'
echo 'Please carefully follow the prompts, this script can take 5 minutes or more depending on your environment.'

# Find out the region where the majority of their resources are deployed
echo 'Please enter your AWS Region (for example us-east-1 or us-west-2):'
read myRegion
echo 'Please provide a namespace (naming prefix) for resource creation:'
read myNameSpace

myNameSpace+=''
kStreamName="${myNameSpace}${kStreamPrefix}${myRegion}"
userName="${myNameSpace}blumirakinesisaccess"

function createIAMKinesisIntegration() {
    # Create Kinesis Stream
    echo "Creating the Kinesis Stream..."
    aws kinesis create-stream \
        --stream-name $kStreamName \
        --shard-count 1 \
        --region $myRegion \
        > /dev/null

    # Get the ARN for the Kinesis Stream that was just created
    kStreamARN=$(aws kinesis describe-stream --stream-name $kStreamName --query 'StreamDescription.StreamARN' --output text)
    # Create the the policy document have to use a different delimiter
    sed -e "s,{KINESISARN},$kStreamARN,g" KIAMpolicyTemplate.json > KIAMpolicy.json

    # Create the IAM policy for Blumira
    echo "Creating the IAM policy..."
    kinesisPolicyName="${userName}policy"
    aws iam create-policy \
        --policy-name $kinesisPolicyName \
        --policy-document file://KIAMpolicy.json \
        > /dev/null

    # Get the ARN for the Blumira Kinesis access policy
    bluPolicyARN=$(aws iam list-policies --scope Local --query "Policies[?PolicyName.contains(@,'blumirakinesisaccesspolicy')].Arn" --output text)

    # Create the Blumira user and attach to IAM policy
    echo "Creating the IAM user and attaching the policy..."
    aws iam create-user \
        --user-name $userName \
        > /dev/null
    echo "Attaching policy to user..."
    
    # Attach the policy to the user
    aws iam attach-user-policy \
        --user-name $userName \
        --policy-arn $bluPolicyARN \
        > /dev/null

    # Create Access Key ID and Secret Key for the new Blumira user
    secrectKey=$(aws iam create-access-key --user-name $userName --query 'AccessKey.SecretAccessKey' --output text)
    accessKey=$(aws iam list-access-keys --user-name $userName --query AccessKeyMetadata[].AccessKeyId --output text)
}
function createCWRole() {
    # Create the CloudWatch Roles Required for the Log Groups

    # Step 1 is to create the CW Roles and Policies necessary for the integration
    echo "Creating the CloudWatch IAM role..."
    sed -e "s/{REGION}/$myRegion/g" TrustPolicyForCWLToKinesisTemplate.json > TrustPolicyForCWLToKinesis.json
    aws iam create-role \
        --role-name "${myNameSpace}BlumiraCWLtoKinesisDataStreamRole" \
        --assume-role-policy-document file://TrustPolicyForCWLToKinesis.json \
        > /dev/null

    # Need to get the IAM ARN to plug into the policy
    CWtoKinesisRoleARN=$(aws iam get-role --role-name "${myNameSpace}BlumiraCWLtoKinesisDataStreamRole" --query "Role.Arn" --output text)
    sed -e "s,{ARN},$CWtoKinesisRoleARN,g" PermissionPolicyForCWLToDataStreamTemplate.json > PermissionPolicyForCWLToDataStream.json

    # Taking the IAM policy that was just created and plugging into the role
    echo "Attaching the IAM policy to the CloudWatch role..."
    aws iam put-role-policy \
        --role-name "${myNameSpace}BlumiraCWLtoKinesisDataStreamRole" \
        --policy-name "${myNameSpace}PermissionPolicyForCWLToDataStream" \
        --policy-document file://PermissionPolicyForCWLToDataStream.json \
        > /dev/null

    # Create the roles and policies needed to create event rules
    sed -e "s,{ARN},$kStreamARN,g" ruleIAMserviceroleTemplate.json > ruleIAMservicerole.json
    echo "Creating the Event Service role and attaching policy..."
    aws iam create-role --role-name "${myNameSpace}BlumiraEventServiceRole" \
        --assume-role-policy-document file://TrustPolicyForRules.json \
        > /dev/null
    aws iam put-role-policy \
        --role-name "${myNameSpace}BlumiraEventServiceRole" \
        --policy-name "${myNameSpace}PermissionPolicyEventService" \
        --policy-document file://ruleIAMservicerole.json \
        > /dev/null

    # Create the roles and policies needed to ship logs from VPC to CW
    echo "Creating the VPC to CloudWatch role and attaching policy..."
    aws iam create-role --role-name "${myNameSpace}BlumiraVPCFlowToCWL" \
        --assume-role-policy-document file://BlumiraVPCToCWLTrustPolicy.json \
        > /dev/null
    aws iam put-role-policy \
        --role-name "${myNameSpace}BlumiraVPCFlowToCWL" \
        --policy-name "${myNameSpace}BlumiraVPCFlowToCWL" \
        --policy-document file://BlumiraVPCFlowToCWL.json \
        > /dev/null
}
function createCWLogGroups() {
    # Create the default log groups and rules for the tenant that we will use as part of the Blumira Integration
    echo "Creating CloudWatch log group, rules, and filters..."
    aws logs create-log-group --log-group-name "${myNameSpace}BlumiraCWLogs" \
        > /dev/null
    # This is the creation of the rule, repeated for each type of log
    aws events put-rule --name "${myNameSpace}BlumiraCWLogs" \
        --event-pattern '{"source": ["aws.cloudwatch"]}' \
        --state "ENABLED" \
        --event-bus-name "default" \
        > /dev/null
    # Re-using the new eventRoleARN for all the following rules
    eventRoleARN=$(aws iam get-role --role-name "${myNameSpace}BlumiraEventServiceRole" --query "Role.Arn" --output text)
    cwlRoleARN=$(aws iam get-role --role-name "${myNameSpace}BlumiraCWLtoKinesisDataStreamRole" --query "Role.Arn" --output text)
    aws events put-targets \
        --rule "${myNameSpace}BlumiraCWLogs" \
        --targets "Id"="CWTarget1","Arn"="$kStreamARN","RoleArn"="$eventRoleARN" \
        > /dev/null
    aws logs put-subscription-filter \
        --log-group-name "${myNameSpace}BlumiraCWLogs" \
        --filter-name "${myNameSpace}BlumiraCWFilter" \
        --filter-pattern "" \
        --destination-arn $kStreamARN \
        --role-arn $cwlRoleARN \
        > /dev/null
    
    echo "Creating IAM log group, rules, and filters..."
    aws logs create-log-group --log-group-name "${myNameSpace}BlumiraIAMLogs" \
        > /dev/null
    aws events put-rule --name "${myNameSpace}BlumiraIAMLogs" \
        --event-pattern '{"source": ["aws.iam"]}' \
        --state "ENABLED" \
        --event-bus-name "default" \
        > /dev/null
    aws events put-targets \
        --rule "${myNameSpace}BlumiraIAMLogs" \
        --targets "Id"="IAMTarget1","Arn"="$kStreamARN","RoleArn"="$eventRoleARN" \
        > /dev/null
    aws logs put-subscription-filter \
        --log-group-name "${myNameSpace}BlumiraIAMLogs" \
        --filter-name "${myNameSpace}BlumiraIAMFilter" \
        --filter-pattern "" \
        --destination-arn $kStreamARN \
        --role-arn $cwlRoleARN \
        > /dev/null

    echo "Creating Cloud Shell log group, rules, and filters..."
    aws logs create-log-group --log-group-name "${myNameSpace}BlumiraCShellLogs" \
        > /dev/null
    aws events put-rule --name "${myNameSpace}BlumiraCShellLogs" \
        --event-pattern '{"source": ["aws.cloudshell"]}' \
        --state "ENABLED" \
        --event-bus-name "default" \
        > /dev/null
    aws events put-targets \
        --rule "${myNameSpace}BlumiraCShellLogs" \
        --targets "Id"="CSTarget1","Arn"="$kStreamARN","RoleArn"="$eventRoleARN" \
        > /dev/null
    aws logs put-subscription-filter \
        --log-group-name "${myNameSpace}BlumiraCShellLogs" \
        --filter-name "${myNameSpace}BlumiraCShellFilter" \
        --filter-pattern "" \
        --destination-arn $kStreamARN \
        --role-arn $cwlRoleARN \
        > /dev/null

    # Ask about the other log groups for VPC Flow Logs, Guard Duty, etc.
    echo "**Enabling GuardDuty is an additional service and cost.**"
    echo "**This portion will NOT enable Guardduty or create detectors.**"
    echo "Do you want to ship GuardDuty logs? (y/n)"
    read guardDuty
    if [[ $guardDuty == "y" ]]; then
        echo "Creating GuardDuty log group, rules, and filters..."
        aws logs create-log-group --log-group-name "${myNameSpace}BlumiraGDLogs" \
            > /dev/null
        aws events put-rule --name "${myNameSpace}BlumiraGDLogs" \
            --event-pattern '{"source": ["aws.guardduty"]}' \
            --state "ENABLED" \
            --event-bus-name "default" \
            > /dev/null
        aws events put-targets \
            --rule "${myNameSpace}BlumiraGDLogs" \
            --targets "Id"="GDTarget1","Arn"="$kStreamARN","RoleArn"="$eventRoleARN" \
            > /dev/null
        aws logs put-subscription-filter \
            --log-group-name "${myNameSpace}BlumiraGDLogs" \
            --filter-name "${myNameSpace}BlumiraGDFilter" \
            --filter-pattern "" \
            --destination-arn $kStreamARN \
            --role-arn $cwlRoleARN \
            > /dev/null
    fi
    echo "Do you want to ship CloudTrail logs? (y/n)"
    read cloudTrail
    if [[ $cloudTrail == "y" ]]; then
        echo "Creating CloudTrail log group, rules, and filters..."
        aws logs create-log-group --log-group-name "${myNameSpace}BlumiraCTLogs" \
            > /dev/null
        aws events put-rule --name "${myNameSpace}BlumiraCTLogs" \
            --event-pattern '{"source": ["aws.cloudtrail"]}' \
            --state "ENABLED" \
            --event-bus-name "default" \
            > /dev/null
        aws events put-targets \
            --rule "${myNameSpace}BlumiraCTLogs" \
            --targets "Id"="CTTarget1","Arn"="$kStreamARN","RoleArn"="$eventRoleARN" \
            > /dev/null
        aws logs put-subscription-filter \
            --log-group-name "${myNameSpace}BlumiraCTLogs" \
            --filter-name "${myNameSpace}BlumiraCTFilter" \
            --filter-pattern "" \
            --destination-arn $kStreamARN \
            --role-arn $cwlRoleARN \
            > /dev/null
        cloudtrailSettings
    fi
    echo "Do you want to ship VPC flow logs? (y/n)"
    read VPC
    if [[ $VPC == "y" ]]; then
        # This log group is different than the above due to Flow logs being different in general setup
        echo "Creating VPC flow log group, rules, and filters..."
        aws logs create-log-group --log-group-name "${myNameSpace}BlumiraVPCLogs" \
        > /dev/null
        echo 'Waiting for VPC Flow Log Group Creation...'
        sleep 30s
        createVPCFlowLogs
        aws logs put-subscription-filter \
            --log-group-name "${myNameSpace}BlumiraVPCLogs" \
            --filter-name "${myNameSpace}BlumiraVPCFilter" \
            --filter-pattern '[version, account_id, interface_id, srcaddr != "-", dstaddr != "-", srcport != "-", dstport != "-", protocol, packets, bytes, start, end, action, log_status]' \
            --destination-arn $kStreamARN \
            --role-arn $cwlRoleARN \
            > /dev/null
    fi
}
function createVPCFlowLogs() {
    # Get the VPC ids of all VPCs in the tenant
    vpcIDs=$(aws ec2 describe-vpcs --query "Vpcs[].VpcId" --output text)
    # Loop through the output because AWS can't intake a tsv list
    # Sets the location to Cloudwatch log group created in separate function
    # Can be skipped if the answer is not given in the above section
    echo "Looping through VPCs to direct Flow Logs to CloudWatch..."
    for vpcID in ${vpcIDs//\t/}; do
        aws ec2 create-flow-logs \
            --resource-ids $vpcID \
            --resource-type "VPC" \
            --traffic-type "ALL" \
            --deliver-logs-permission-arn $(aws iam get-role --role-name "${myNameSpace}BlumiraVPCFlowToCWL" --query "Role.Arn" --output text) \
            --log-destination-type cloud-watch-logs \
            --log-destination $(aws logs describe-log-groups --log-group-name-pattern "${myNameSpace}BlumiraVPCLogs" --query "logGroups[].arn" --output text) \
            > /dev/null
    done
}
function cloudtrailSettings() {
    # Set the bucket name and then convert to lowercase
    echo "Creating S3 Bucket for CloudTrail..."
    bucketName="${myNameSpace}BlumiraCTrailBucket"
    bucketNameLower="${bucketName,,}"
    # Create the S3 bucket
    aws s3api create-bucket \
        --acl private \
        --bucket $bucketNameLower \
        > /dev/null
    # Grab the account ID for the AWS tenant so that we can create the proper bucket policy and role for cloud trail
    accountID=$(aws sts get-caller-identity --query "Account" --output text)
    sed -e "s,{BUCKETNAME},$bucketNameLower,g; s,{ACCOUNTID},$accountID,g; s,{TRAILNAME},${myNameSpace}BlumiraCTrail,g; s,{REGION},$myRegion,g" S3bucketpolicytemplate.json > S3bucketpolicy.json
    # Take the bucket policies and apply them
    echo "Creating S3 Bucket Policies..."
    aws s3api put-bucket-policy \
        --bucket $bucketNameLower \
        --policy file://S3bucketpolicy.json \
        > /dev/null
    # Create and set the bucket lifecycle policy
    aws s3api put-bucket-lifecycle-configuration \
        --bucket $bucketNameLower \
        --lifecycle-configuration file://S3LifeCycle.json \
        > /dev/null
    # Get the log group ARN for where we want cloudtrail to send logs to in cloudwatch
    ctLogGroupArn=$(aws logs describe-log-groups --log-group-name-prefix "${myNameSpace}BlumiraCTLogs" --query "logGroups[].arn" --output text)
    ctLogGroupArnTemp=${ctLogGroupArn::-1}
    ctLogGroupArnForTemplate="${ctLogGroupArnTemp}log-stream:${accountID}_CloudTrail_${myRegion}*"
    # Set the cloudtrail role name as a variable
    ctRoleName="${myNameSpace}BlumiraCloudTrailToCloudWatch"
    sed -e "s,{LOGGROUPARN},$ctLogGroupArnForTemplate,g; s,{ROLEName},$ctRoleName,g" CTIAMroletemplate.json > CTIAMpolicy.json
    # Create the roles for Cloudtrail to Cloudwatch and set the trust policy
    echo "Creating the CloudTrail roles and trust policy..."
    aws iam create-role --role-name $ctRoleName \
        --assume-role-policy-document file://CTtoCWTrustPolicy.json \
        > /dev/null
    aws iam put-role-policy \
        --role-name $ctRoleName \
        --policy-name "${ctRoleName}Policy" \
        --policy-document file://CTIAMpolicy.json \
        > /dev/null
    # Get the cloudtrail role arn for creation of the trail itself
    ctRoleArn=$(aws iam get-role --role-name $ctRoleName --query "Role.Arn" --output text)
    # Create the trail and start logging
    echo "Creating the trail and starting logging..."
    sleep 30s
    aws cloudtrail create-trail \
        --name "${myNameSpace}BlumiraCTrail" \
        --s3-bucket-name $bucketNameLower \
        --cloud-watch-logs-log-group-arn $ctLogGroupArn \
        --cloud-watch-logs-role-arn $ctRoleArn \
        --no-enable-log-file-validation \
        --include-global-service-events \
        --is-multi-region-trail \
        > /dev/null
    aws cloudtrail start-logging --name "${myNameSpace}BlumiraCTrail" \
        > /dev/null
    # Change the public access policy of the s3 bucket
    aws s3api put-public-access-block \
        --bucket $bucketNameLower \
        --public-access-block-configuration "BlockPublicAcls"="true","IgnorePublicAcls"="true","BlockPublicPolicy"="true","RestrictPublicBuckets"="true" \
        > /dev/null
    echo -e "You will need to modify the Trail Event Types to include Data Events and Insight Events."
}

createIAMKinesisIntegration
echo "Waiting for resource creation to complete, please wait..."
sleep 30s
createCWRole
echo "Waiting for resources creation to complete, please wait..."
sleep 30s
createCWLogGroups
echo "Validating, please wait..."
sleep 30s

echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo -e "\n"
echo -e "Please use the Stream Name, Access Key ID, Secret, and Region\nwithin Blumira to create your Cloud Connector"
echo "Stream Name: "$kStreamName
echo "Access Key ID: "$accessKey
echo "Secret Key: "$secrectKey
echo "Region: "$myRegion
echo -e "\n"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++"
endDateTime=$(date)
echo "Script started at: "$startDateTime
echo "Script ended at: "$endDateTime
