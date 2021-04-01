#
# Table structure for table equiv of yubikey_mapping
#

CREATE TABLE IF NOT EXISTS  `otp`.`yubikey_mappings` (
  `otp_id` VARCHAR(12) NOT NULL ,
  `username` VARCHAR(64) NOT NULL ,
  PRIMARY KEY  (`otp_id`(12))
  );
