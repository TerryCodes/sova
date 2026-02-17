-- Migration v7: Add encryption support for attachments
PRAGMA foreign_keys=OFF;

ALTER TABLE attachment_message ADD COLUMN encrypted INTEGER NOT NULL DEFAULT 0;
ALTER TABLE attachment_message ADD COLUMN iv TEXT;

PRAGMA foreign_keys=ON;
