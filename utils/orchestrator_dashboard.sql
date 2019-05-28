--
-- Table structure for table `deployments`
--

CREATE TABLE IF NOT EXISTS `deployments` (
  `uuid` varchar(36) NOT NULL,
  `creation_time` datetime DEFAULT NULL,
  `update_time` datetime DEFAULT NULL,
  `physicalId` varchar(36) DEFAULT NULL,
  `description` varchar(256) DEFAULT NULL,
  `status` varchar(128) DEFAULT NULL,
  `outputs` mediumtext,
  `task` varchar(64) DEFAULT NULL,
  `links` mediumtext,
  `sub` varchar(36) DEFAULT NULL,
  `provider_name` varchar(128) DEFAULT NULL,
  `endpoint` varchar(256) DEFAULT NULL,
  `template` longtext,
  `inputs` mediumtext,
  `params` mediumtext,
  `locked` tinyint(1) DEFAULT '0',
  `feedback_required` tinyint(1) DEFAULT '1',
  `remote` tinyint(1) DEFAULT '0',
  `issuer` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`uuid`)
);

--
-- Table structure for table `users`
--

CREATE TABLE IF NOT EXISTS `users` (
  `sub` varchar(36) NOT NULL,
  `name` varchar(128) DEFAULT NULL,
  `username` varchar(64) NOT NULL,
  `given_name` varchar(64) DEFAULT NULL,
  `family_name` varchar(64) DEFAULT NULL,
  `email` varchar(64) NOT NULL,
  `organisation_name` varchar(64) DEFAULT NULL,
  `picture` varchar(128) DEFAULT NULL,
  `role` varchar(32) DEFAULT 'user',
  `active` tinyint(1) DEFAULT '1',
  PRIMARY KEY (`sub`)
);

