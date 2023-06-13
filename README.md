# AWShim
AWS configurations for logging through the various services can now be automated, simplifying the configuration steps and getting logs ingested even faster. This tool will create the requisite streams, policies, users, permissions, and resources for getting logs from __Cloudwatch__, __Cloudtrail__, __GuardDuty__, and __VPC flow logs__.

## Getting Started
You will need an account in AWS that has access to the __AWS CloudShell__ interface in the __Management Console__. Your account must also be able to create IAM roles, users, and policies. In addition to those permissions, you must be able to create resources within AWS.

## Steps
Sign in to the __Management Console__ in AWS.

Now click on the __AWS CloudShell__ button in the top right hand corner of the screen. It will look like a box with the “>.” symbol inside.

Once the CLI starts up you will be presented with a window that will look similar to what is shown below. Indicating that the __CloudShell__ is ready to start taking commands.

Now you will need to run the following commands:
```Bash
git clone https://github.com/Blumira/AWShim
cd ./AWShim
chmod +x ./AWShim.sh
./AWShim.sh -c
```
There are a few prompts in this script please read carefully and answer based on what is in your AWS environment, the prompts are listed below:
* Please enter your Region (for example us-east-1 or us-west-2)
* Do you want to ship GuardDuty logs? (y/n)
* Do you want to ship VPC Flow logs? (y/n)

You will see the output from several commands, which can be ignored. Once the script is done running you will see an output that is preceded by two lines of ‘*’ followed by the information that you will need to use inside of Blumira (shown below).

## Configuring AWS Cloud Connector
Once the script is completed copy the Stream Name, Access Key ID, Secret Key, and Region. Navigate to Blumira. Once inside your Blumira account, go to __Settings>Cloud Connectors__. Click “+ Cloud Connector”. Then paste in the values that were copied from the script’s output. Once done click “Connect”.

## Additional Notes:

Resources Created:
* Kinesis Stream
* Cloudwatch Log Groups
* Cloudwatch Rules
* Cloudtrail Trail
* S3 Bucket (for Trail)
* IAM user and several roles
* Event Service role
* Cloudwatch role for shipping logs to stream
* Cloudtrail to cloudwatch role
* VPC to Cloudwatch role

All resources will be namespaced by a unique epoch date/time to more easily find what is being created.

