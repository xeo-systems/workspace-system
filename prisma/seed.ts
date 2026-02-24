import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  const permissions = [
    { key: "org.read", description: "Read organizations" },
    { key: "org.write", description: "Write organizations" },
    { key: "workspace.read", description: "Read workspaces" },
    { key: "workspace.write", description: "Write workspaces" },
    { key: "audit.view", description: "View audit logs" },
    { key: "jobs.run", description: "Run jobs" },
    { key: "members.invite", description: "Invite members" },
    { key: "members.manage", description: "Manage members" }
  ];

  for (const p of permissions) {
    await prisma.permission.upsert({
      where: { key: p.key },
      update: { description: p.description },
      create: p
    });
  }

  async function getOrCreateRole(params: {
    name: string;
    scope: "ORG" | "WORKSPACE";
    description?: string;
  }) {
    const existing = await prisma.role.findFirst({
      where: { orgId: null, scope: params.scope, name: params.name }
    });
    if (existing) {
      return existing;
    }
    return prisma.role.create({
      data: {
        name: params.name,
        scope: params.scope,
        description: params.description ?? null,
        orgId: null
      }
    });
  }

  const orgOwner = await getOrCreateRole({
    name: "owner",
    scope: "ORG",
    description: "Organization owner"
  });
  const orgAdmin = await getOrCreateRole({
    name: "admin",
    scope: "ORG",
    description: "Organization admin"
  });
  const orgMember = await getOrCreateRole({
    name: "member",
    scope: "ORG",
    description: "Organization member"
  });
  const orgViewer = await getOrCreateRole({
    name: "viewer",
    scope: "ORG",
    description: "Organization viewer"
  });

  const wsAdmin = await getOrCreateRole({
    name: "admin",
    scope: "WORKSPACE",
    description: "Workspace admin"
  });
  const wsEditor = await getOrCreateRole({
    name: "editor",
    scope: "WORKSPACE",
    description: "Workspace editor"
  });
  const wsViewer = await getOrCreateRole({
    name: "viewer",
    scope: "WORKSPACE",
    description: "Workspace viewer"
  });

  const permissionByKey = new Map(
    (await prisma.permission.findMany()).map((p) => [p.key, p])
  );

  const rolePermissions: Array<[string, string[]]> = [
    [
      "org.owner",
      [
        "org.read",
        "org.write",
        "workspace.read",
        "workspace.write",
        "audit.view",
        "jobs.run",
        "members.invite",
        "members.manage"
      ]
    ],
    [
      "org.admin",
      [
        "org.read",
        "org.write",
        "workspace.read",
        "workspace.write",
        "audit.view",
        "jobs.run",
        "members.invite",
        "members.manage"
      ]
    ],
    ["org.member", ["org.read", "workspace.read"]],
    ["org.viewer", ["org.read", "workspace.read"]],
    ["workspace.admin", ["workspace.read", "workspace.write", "audit.view"]],
    ["workspace.editor", ["workspace.read", "workspace.write"]],
    ["workspace.viewer", ["workspace.read"]]
  ];

  const roleByKey = new Map([
    ["org.owner", orgOwner],
    ["org.admin", orgAdmin],
    ["org.member", orgMember],
    ["org.viewer", orgViewer],
    ["workspace.admin", wsAdmin],
    ["workspace.editor", wsEditor],
    ["workspace.viewer", wsViewer]
  ]);

  for (const [roleKey, perms] of rolePermissions) {
    const role = roleByKey.get(roleKey);
    if (!role) continue;
    for (const permKey of perms) {
      const perm = permissionByKey.get(permKey);
      if (!perm) continue;
      await prisma.rolePermission.upsert({
        where: {
          roleId_permissionId: { roleId: role.id, permissionId: perm.id }
        },
        update: {},
        create: { roleId: role.id, permissionId: perm.id }
      });
    }
  }
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });
