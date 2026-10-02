import ComingSoon from "@/ui/ComingSoon";

export default function UsersPage() {
  return (
    <ComingSoon
      title="Users / Roles"
      milestone="RBAC core built (M7); management UI later"
      description="Capability + scope bindings and RLS tenant isolation are built and enforced server-side. A user/role management surface is not built yet; fine-grained/enterprise roles are V2."
      horizonsRef="§1 (item 43), §7 (item 32)"
      planned={[
        "User directory and invitation flow",
        "Role and scope binding editor",
        "Full RBAC-SC conditions (V2)",
      ]}
    />
  );
}
