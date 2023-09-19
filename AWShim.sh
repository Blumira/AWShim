#!/bin/bash
# Author: Justin Kikani 
# Last Modified: 09/18/2022
# Version: 1.0.2
# Release Notes: Initial Release!
# Purpose: To simplify and standardize the creation of the resources, 
# permissions, and policies needed to be able to create a Cloud Connector
# within the Blumira platform.
# Notice: We/I am not responsible for additional cloud costs incurred due to this script.

# To run this script please go to your AWS management console and run git clone git clone https://github.com/Blumira/AWShim.
# CD into the directory.
# Use chmod +X to make this script executable and then run this script.
# TODO: Cleanup/optimize cleanup functions, add more descriptive language to help

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

function Help() {
    echo "AWShim is an automated deployment tool for configuring your AWS environment for Blumira."
    echo "WARNING! THIS SCRIPT USES THE DATE/TIME FOR NAMESPACING RESOURCES"
    echo "IF IT HAS BEEN MORE THAN 1 DAY IT WILL CREATE ALL NEW RESOURCES"
    echo "Valid syntax will include AWShim.sh -h|-c|-u"
}

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
    bluPolicyARN=$(aws iam list-policies --scope Local --query "Policies[?PolicyName == '$kinesisPolicyName'].Arn" --output text)

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
        > /dev/null # Appears to be this command that is causing the issue

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

    # Ask about the other log groups for VPC Flow Logs, Guard Duty, etc.
    echo "**Enabling GuardDuty is an additional service and cost thru Amazon.**"
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
    # Removing the location constraint as it is now causing deployment issues
    if [ "$myRegion" = "us-east-1" ]; then
        aws s3api create-bucket \
            --acl private \
            --bucket $bucketNameLower \
            --region $myRegion \
            > /dev/null
    else
        aws s3api create-bucket \
            --acl private \
            --bucket $bucketNameLower \
            --region $myRegion \
            --create-bucket-configuration LocationConstraint=$myRegion
            > /dev/null
    fi
    sleep 30s
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

function cleanupFiles() {
    # Cleanup the files that were created in earlier steps
    rm KIAMpolicy.json
    rm TrustPolicyForCWLToKinesis.json
    rm PermissionPolicyForCWLToDataStream.json
    rm ruleIAMservicerole.json
    rm CTIAMpolicy.json
    touch KIAMpolicy.json
    touch TrustPolicyForCWLToKinesis.json
    touch PermissionPolicyForCWLToDataStream.json
    touch PermissionPolicyForCWLToDataStream.json
    touch ruleIAMservicerole.json
    touch CTIAMpolicy.json
}

function removeBlumiraConfigs() {
    
    # Set the namespace for querying resources
    myNameSpace=$1
    
    echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    echo "WARNING! This will delete your Blumira AWS configurations."
    echo "Please confirm that you want to proceed."
    while true; do
        read -p "$* [y/n]: " yn
        case $yn in
            [Yy]*)
                # Remove Streams
                echo "Removing Blumira Kinesis Stream..."
                kinesisStreams2Remove=$(aws kinesis list-streams --query "StreamSummaries[?StreamARN.contains(@, '$myNameSpace')].StreamARN" --output text)
                aws kinesis delete-stream --stream-arn $kinesisStreams2Remove
            
                # Remove Users and IAM Configurations
                echo "Removing Blumira IAM User..."
                IAMpolicyArn2Remove=$(aws iam list-policies --query "Policies[?Arn.contains(@,'$myNameSpace')].Arn" --output text)
                IAMusers2Remove=$(aws iam list-users --query "Users[?Arn.contains(@, '$myNameSpace')].UserName" --output text)
                IAMaccessKeyId2Remove=$(aws iam list-access-keys --user-name $IAMusers2Remove --query "AccessKeyMetadata[].AccessKeyId" --output text)
                aws iam detach-user-policy --user-name $IAMusers2Remove --policy-arn $IAMpolicyArn2Remove
                aws iam delete-policy --policy-arn $IAMpolicyArn2Remove
                aws iam delete-access-key --user-name $IAMusers2Remove --access-key-id $IAMaccessKeyId2Remove
                aws iam delete-user --user-name $IAMusers2Remove
                
                # Remove Roles
                echo "Removing additional Blumira IAM roles..."
                IAMrole2Remove1=$(aws iam list-roles --query "Roles[?RoleName.contains(@, '$myNameSpace')].RoleName" --output text | awk '{print $1}')
                IAMrole2Remove2=$(aws iam list-roles --query "Roles[?RoleName.contains(@, '$myNameSpace')].RoleName" --output text | awk '{print $2}')
                IAMrole2Remove3=$(aws iam list-roles --query "Roles[?RoleName.contains(@, '$myNameSpace')].RoleName" --output text | awk '{print $3}')
                IAMrole2Remove4=$(aws iam list-roles --query "Roles[?RoleName.contains(@, '$myNameSpace')].RoleName" --output text | awk '{print $4}')
                IAMrolePolicy2Remove1=$(aws iam list-role-policies --role-name $IAMrole2Remove1 --query PolicyNames[] --output text)
                IAMrolePolicy2Remove2=$(aws iam list-role-policies --role-name $IAMrole2Remove2 --query PolicyNames[] --output text)
                IAMrolePolicy2Remove3=$(aws iam list-role-policies --role-name $IAMrole2Remove3 --query PolicyNames[] --output text)
                IAMrolePolicy2Remove4=$(aws iam list-role-policies --role-name $IAMrole2Remove4 --query PolicyNames[] --output text)
                aws iam delete-role-policy --role-name $IAMrole2Remove1 --policy-name $IAMrolePolicy2Remove1
                aws iam delete-role-policy --role-name $IAMrole2Remove2 --policy-name $IAMrolePolicy2Remove2
                aws iam delete-role-policy --role-name $IAMrole2Remove3 --policy-name $IAMrolePolicy2Remove3
                aws iam delete-role-policy --role-name $IAMrole2Remove4 --policy-name $IAMrolePolicy2Remove4
                aws iam delete-role --role-name $IAMrole2Remove1
                aws iam delete-role --role-name $IAMrole2Remove2
                aws iam delete-role --role-name $IAMrole2Remove3
                aws iam delete-role --role-name $IAMrole2Remove4

                # Remove Log Groups
                echo "Removing Log Groups..."
                aws logs delete-log-group --log-group-name $(aws logs describe-log-groups --query "logGroups[?logGroupName=='${myNameSpace}BlumiraCShellLogs'].logGroupName" --output text)
                aws logs delete-log-group --log-group-name $(aws logs describe-log-groups --query "logGroups[?logGroupName=='${myNameSpace}BlumiraCWLogs'].logGroupName" --output text)
                aws logs delete-log-group --log-group-name $(aws logs describe-log-groups --query "logGroups[?logGroupName=='${myNameSpace}BlumiraIAMLogs'].logGroupName" --output text)
                aws logs delete-log-group --log-group-name $(aws logs describe-log-groups --query "logGroups[?logGroupName=='${myNameSpace}BlumiraCTLogs'].logGroupName" --output text)

                # Remove Event Rules
                echo "Removing Blumira Targets by Rules..."
                target2Delete=$(aws events list-targets-by-rule \
                    --rule $(aws events list-rules --query "Rules[?Name=='${myNameSpace}BlumiraCShellLogs'].Name" --output text) \
                    --query "Targets[].Id" \
                    --output text)
                aws events remove-targets --rule $(aws events list-rules --query "Rules[?Name=='${myNameSpace}BlumiraCShellLogs'].Name" --output text) \
                    --ids $target2Delete \
                    > /dev/null
                target2Delete=$(aws events list-targets-by-rule \
                    --rule $(aws events list-rules --query "Rules[?Name=='${myNameSpace}BlumiraCWLogs'].Name" --output text) \
                    --query "Targets[].Id" \
                    --output text)
                aws events remove-targets --rule $(aws events list-rules --query "Rules[?Name=='${myNameSpace}BlumiraCWLogs'].Name" --output text) \
                    --ids $target2Delete \
                    > /dev/null
                target2Delete=$(aws events list-targets-by-rule \
                    --rule $(aws events list-rules --query "Rules[?Name=='${myNameSpace}BlumiraIAMLogs'].Name" --output text) \
                    --query "Targets[].Id" \
                    --output text)
                aws events remove-targets --rule $(aws events list-rules --query "Rules[?Name=='${myNameSpace}BlumiraIAMLogs'].Name" --output text) \
                    --ids $target2Delete \
                    > /dev/null
                target2Delete=$(aws events list-targets-by-rule \
                    --rule $(aws events list-rules --query "Rules[?Name=='${myNameSpace}BlumiraCTLogs'].Name" --output text) \
                    --query "Targets[].Id" \
                    --output text)
                aws events remove-targets --rule $(aws events list-rules --query "Rules[?Name=='${myNameSpace}BlumiraCTLogs'].Name" --output text) \
                    --ids $target2Delete \
                    > /dev/null
                echo "Removing Blumira Rules..."
                aws events delete-rule \
                    --name $(aws events list-rules --query "Rules[?Name=='${myNameSpace}BlumiraCShellLogs'].Name" --output text)
                aws events delete-rule \
                    --name $(aws events list-rules --query "Rules[?Name=='${myNameSpace}BlumiraCWLogs'].Name" --output text)
                aws events delete-rule \
                    --name $(aws events list-rules --query "Rules[?Name=='${myNameSpace}BlumiraIAMLogs'].Name" --output text)
                aws events delete-rule \
                    --name $(aws events list-rules --query "Rules[?Name=='${myNameSpace}BlumiraCTLogs'].Name" --output text)
                
                # Remove Trails
                echo "Removing Blumira CloudTrail Trail configurations..."
                aws cloudtrail delete-trail --name "${myNameSpace}BlumiraCTrail"

                # Remove Bucket
                echo "Deleting Blumira Bucket Data..."
                aws s3 rm "s3://${myNameSpace}blumiractrailbucket/" --recursive \
                    > /dev/null
                echo "Removing Blumira Bucket..."
                aws s3 rb "s3://${myNameSpace}blumiractrailbucket/" --force \
                > /dev/null

                # Checking for GuardDuty
                echo "Checking for Blumira GuardDuty configurations..."
                doesGDLogGroupExist=$(aws logs describe-log-groups --query "logGroups[?logGroupName=='${myNameSpace}BlumiraGDLogs'].logGroupName" --output text)
                if [ -n "$doesGDLogGroupExist" ]; then
                    echo "WARNING! This script will not disable GuardDuty."
                    echo "Removing Blumira GuardDuty configurations..."
                    aws logs delete-log-group --log-group-name $doesGDLogGroupExist
                    target2Delete=$(aws events list-targets-by-rule \
                    --rule $(aws events list-rules --query "Rules[?Name=='${myNameSpace}BlumiraGDLogs'].Name" --output text) \
                    --query "Targets[].Id" \
                    --output text)
                    aws events remove-targets --rule $(aws events list-rules --query "Rules[?Name=='${myNameSpace}BlumiraGDLogs'].Name" --output text) \
                        --ids $target2Delete \
                        > /dev/null
                    aws events delete-rule \
                        --name $(aws events list-rules --query "Rules[?Name=='${myNameSpace}BlumiraGDLogs'].Name" --output text)
                else
                    echo "No Blumira GuardDuty configurations found, skipping..."
                fi

                # Checking for VPC Flow Logs
                doesVPCLogGroupExist=$(aws logs describe-log-groups --query "logGroups[?logGroupName=='${myNameSpace}BlumiraVPCLogs'].logGroupName" --output text)
                if [ -n "$doesVPCLogGroupExist" ]; then
                    echo "Removing Blumira VPC Flow Log Group..."
                    vpcIDs=$(aws ec2 describe-vpcs --query "Vpcs[].VpcId" --output text)
                    echo "Removing Blumira VPC Flow Log configurations..."
                    for vpcID in ${vpcIDs//\t/}; do
                        flowLog2Delete=$(aws ec2 describe-flow-logs \
                            --filter "Name=resource-id,Values=${vpcID}" \
                            --query "FlowLogs[?LogGroupName.contains(@, '${myNameSpace}')].FlowLogId" \
                            --output text)
                        aws ec2 delete-flow-logs \
                            --flow-log-ids $flowLog2Delete \
                            > /dev/null
                    done
                else
                    echo "No Blumira VPC Flow Log configurations found, skipping..."
                fi

                return 0;;
            [Nn]*)
                echo "Aborting, no configurations have been removed." 
                return  1;;
        esac
    done
}

# Main Program Section
while getopts ":hcut" option; do
    case $option in
        h) # display Help
            Help
            exit;;
        c)
            # Output Date/Time for Start
            startDateTime=$(date)
            myNameSpace=$(date -d "${startDateTime}" +"%s")

            # Standardized Blumira Kinesis Data Stream name
            kStreamPrefix="blumirastream"

            # Script Preamble
            echo "WARNING! THIS SCRIPT USES THE DATE/TIME FOR NAMESPACING RESOURCES"
            echo "EACH RUN WILL CREATE NEW CONFIGURATIONS."
            echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++"
            echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++"
            echo 'Welcome to AWShim'
            echo 'Please carefully follow the prompts, this script can take 5 minutes or more depending on your environment.'

            # Find out the region where the majority of their resources are deployed
            echo 'Please enter your AWS Region (for example us-east-1 or us-west-2):'
            read myRegion

            kStreamName="${myNameSpace}${kStreamPrefix}"
            userName="${myNameSpace}blumirakinesisaccess"

            createIAMKinesisIntegration
            echo "Waiting for resource creation to complete, please wait..."
            sleep 30s
            createCWRole
            echo "Waiting for resources creation to complete, please wait..."
            sleep 30s
            createCWLogGroups
            echo "Validating, please wait..."
            sleep 30s
            echo "Cleaning up generated json configuration files..."
            cleanupFiles

            echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++"
            echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++"
            echo -e "\n"
            echo -e "Please use the Stream Name, Access Key ID, Secret, and Region\nwithin Blumira to create your Cloud Connector."
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
            echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++"
            echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++"
            echo "Please document the following uninstall command in case you need to remove Blumira configurations:"
            echo "./AWShim.sh -u "$myNameSpace
            exit;;
        u)  
            echo "Removing Blumira configurations and Blumira logging resources..."
            removeBlumiraConfigs $2
            exit;;
        t)
            # Dev/Test Option
            startDateTime=$(date)
            myNameSpace=$(date -d "${startDateTime}" +"%s")
            echo $myNameSpace
            exit;;
        \?)
            echo "Invalid option, please try again with one of the valid options -h|-c|-u"
            exit;;
    esac
done
