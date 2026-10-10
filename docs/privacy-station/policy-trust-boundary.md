# Policy trust boundary — sagitarrius-broker

## Finding

`sagitarrius-broker call` accepts both `--policy` and `--request` from its
invoker. If the invoker is an untrusted agent, the agent can supply a
permissive policy file, choose a matching grant ID, and obtain broader
access than the operator intended. Policy validation, file permissions, and
file ownership do not fix this: another process with the same user identity
and filesystem access can create or select another policy file.

The broker process has no reliable way to distinguish:

- a trusted operator shell invoking the broker with an approved policy; from
- an untrusted agent invoking the same binary with an attacker-written policy.

## Supported model

Direct invocation by an untrusted agent is unsupported. A trusted operator
or launcher must:

1. select the policy file;
2. supply the master password through a channel the agent cannot observe; and
3. give the agent control only over the request file, if the deployment
   exposes requests to the agent at all.

This boundary is architectural. It must be enforced by process invocation,
sandboxing, and secret handling outside the broker binary.

## Options considered

1. **Trusted launcher with policy descriptor.**
   A launcher controlled by the operator invokes the broker and retains
   exclusive control over policy selection. The agent may submit a request
   to the launcher, but cannot execute the broker or change its arguments.
   This is the recommended model, but it requires deployment work outside
   this repository.

2. **Policy allowlist anchored outside agent control.**
   The broker could accept only a policy whose digest appears in an
   operator-controlled allowlist. This works only if the agent cannot
   replace both the policy and the allowlist. With the same user identity
   and writable filesystem access, it cannot provide the boundary by itself.

3. **Mandatory-access controls or separate user identities.**
   OS users, containers, or sandbox profiles could prevent the agent from
   writing/selecting policy material while permitting it to submit a
   request. This is deployment-specific and is not implemented here.

4. **Policy signatures.**
   An operator signature over the policy would move trust from invocation to
   cryptography. This needs a new signature format/dependency and human
   approval, so it is not implemented in this remediation.

## Decision needed

The human must approve either the trusted-launcher deployment contract or a
follow-up change to the broker's command surface. Until then, PS-01 does not
claim that an agent-controlled `--policy` argument is safe.
