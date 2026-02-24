/*
  Warnings:

  - A unique constraint covering the columns `[id,organizationId]` on the table `Workspace` will be added. If there are existing duplicate values, this will fail.

*/
-- DropForeignKey
ALTER TABLE "Membership" DROP CONSTRAINT "Membership_workspaceId_fkey";

-- CreateIndex
CREATE UNIQUE INDEX "Workspace_id_organizationId_key" ON "Workspace"("id", "organizationId");

-- AddForeignKey
ALTER TABLE "Membership" ADD CONSTRAINT "Membership_workspaceId_organizationId_fkey" FOREIGN KEY ("workspaceId", "organizationId") REFERENCES "Workspace"("id", "organizationId") ON DELETE CASCADE ON UPDATE CASCADE;
