-- CreateTable
CREATE TABLE `User` (
    `id` VARCHAR(191) NOT NULL,
    `email` VARCHAR(191) NOT NULL,
    `password` VARCHAR(191) NOT NULL,
    `role` ENUM('security', 'engineer', 'contractor', 'finance') NOT NULL DEFAULT 'engineer',
    `mfa` BOOLEAN NOT NULL DEFAULT false,
    `lastLogin` BIGINT NULL,
    `logins24h` INTEGER NOT NULL DEFAULT 0,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `User_email_key`(`email`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `VirtualMachine` (
    `id` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `cpuPercent` INTEGER NOT NULL,
    `isIdle` BOOLEAN NOT NULL DEFAULT false,
    `kwhMonthly` DOUBLE NOT NULL DEFAULT 0,
    `costMonthly` DOUBLE NOT NULL DEFAULT 0,
    `isOversized` BOOLEAN NOT NULL DEFAULT false,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `StorageBucket` (
    `id` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `isPublic` BOOLEAN NOT NULL DEFAULT false,
    `isEncrypted` BOOLEAN NOT NULL DEFAULT true,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `StorageBucket_name_key`(`name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ScannedFile` (
    `id` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `href` VARCHAR(191) NULL,
    `url` VARCHAR(191) NULL,
    `ext` VARCHAR(191) NULL,
    `cloudProvider` VARCHAR(191) NULL,
    `riskScore` INTEGER NOT NULL DEFAULT 0,
    `verdict` ENUM('safe', 'suspicious', 'malicious') NOT NULL DEFAULT 'safe',
    `scannedAt` BIGINT NULL,
    `probed` BOOLEAN NOT NULL DEFAULT false,
    `actualType` VARCHAR(191) NULL,
    `magicMismatch` VARCHAR(191) NULL,
    `contentType` VARCHAR(191) NULL,
    `fileSize` BIGINT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `FileThreat` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `fileId` VARCHAR(191) NOT NULL,
    `code` VARCHAR(191) NOT NULL,
    `level` ENUM('critical', 'high', 'medium', 'low') NOT NULL,
    `message` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Alert` (
    `id` VARCHAR(191) NOT NULL,
    `category` ENUM('security', 'file', 'cost', 'anomaly') NOT NULL,
    `description` VARCHAR(191) NOT NULL,
    `priority` ENUM('critical', 'high', 'medium', 'low') NOT NULL,
    `acknowledged` BOOLEAN NOT NULL DEFAULT false,
    `createdAt` BIGINT NOT NULL DEFAULT 0,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `AnomalyEvent` (
    `id` VARCHAR(191) NOT NULL,
    `type` VARCHAR(191) NOT NULL,
    `detail` VARCHAR(191) NOT NULL,
    `severity` ENUM('critical', 'high', 'medium', 'low') NOT NULL DEFAULT 'medium',
    `detectedAt` BIGINT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ThreatSurface` (
    `id` VARCHAR(191) NOT NULL,
    `surfaceName` VARCHAR(191) NOT NULL,
    `status` ENUM('compliant', 'warning', 'critical') NOT NULL,
    `impact` VARCHAR(191) NULL,
    `checkedAt` BIGINT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Recommendation` (
    `id` VARCHAR(191) NOT NULL,
    `icon` VARCHAR(191) NULL,
    `title` VARCHAR(191) NOT NULL,
    `description` VARCHAR(191) NULL,
    `action` VARCHAR(191) NOT NULL,
    `isApplied` BOOLEAN NOT NULL DEFAULT false,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `AuditLog` (
    `id` VARCHAR(191) NOT NULL,
    `timestamp` VARCHAR(191) NOT NULL,
    `eventType` VARCHAR(191) NOT NULL,
    `actor` VARCHAR(191) NULL,
    `resource` VARCHAR(191) NULL,
    `outcome` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ChatMessage` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `role` ENUM('user', 'assistant') NOT NULL,
    `message` VARCHAR(191) NOT NULL,
    `source` ENUM('gemini', 'local') NOT NULL DEFAULT 'local',
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `WorkflowPhase` (
    `phase` INTEGER NOT NULL,
    `title` VARCHAR(191) NOT NULL,
    `description` VARCHAR(191) NULL,
    `requiredRole` VARCHAR(191) NULL,
    `status` ENUM('active', 'pending', 'completed') NOT NULL DEFAULT 'pending',
    `energyEstimate` INTEGER NULL,
    `costEstimate` INTEGER NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    PRIMARY KEY (`phase`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `RiskSnapshot` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `score` INTEGER NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `FileThreat` ADD CONSTRAINT `FileThreat_fileId_fkey` FOREIGN KEY (`fileId`) REFERENCES `ScannedFile`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
