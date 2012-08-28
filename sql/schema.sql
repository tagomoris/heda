CREATE DATABASE IF NOT EXISTS heda DEFAULT CHARACTER SET 'utf8';

CREATE TABLE IF NOT EXISTS heda.users (
  id          INT          NOT NULL PRIMARY KEY AUTO_INCREMENT,
  subid       VARCHAR(32)  NOT NULL UNIQUE,
  username    VARCHAR(32)  NOT NULL UNIQUE,
  passhash    VARCHAR(64)  NOT NULL,  -- SHA256(salt + password)
  fullname    VARCHAR(64)  NOT NULL,
  mailaddress VARCHAR(256) DEFAULT NULL,
  salt        VARCHAR(40)  NOT NULL,  -- SHA1(rand())
  valid       SMALLINT     DEFAULT 0,
  superuser   SMALLINT     DEFAULT 0,
  created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  modified_at TIMESTAMP    NOT NULL DEFAULT '0000-00-00 00:00:00',
  KEY users_authenticate (passhash,username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
