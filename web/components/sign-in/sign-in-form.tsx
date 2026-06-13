"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import {
  ArrowLeftIcon,
  GithubLogoIcon,
  GoogleLogoIcon,
  PaperPlaneTiltIcon,
} from "@phosphor-icons/react"
import { toast } from "sonner"

import { authClient } from "@/lib/auth/auth-client"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Spinner } from "@/components/ui/spinner"

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export function SignInForm({
  googleEnabled,
  githubEnabled,
}: {
  googleEnabled: boolean
  githubEnabled: boolean
}) {
  const router = useRouter()
  const [email, setEmail] = React.useState("")
  const [otp, setOtp] = React.useState("")
  const [step, setStep] = React.useState<"email" | "otp">("email")
  const [pending, setPending] = React.useState<
    null | "otp" | "verify" | "link" | "google" | "github"
  >(null)
  const [error, setError] = React.useState<string | null>(null)
  const [linkSent, setLinkSent] = React.useState(false)

  const normalizedEmail = email.trim().toLowerCase()

  function validateEmail() {
    if (!EMAIL_PATTERN.test(normalizedEmail)) {
      setError("Enter a valid email address.")
      return false
    }
    setError(null)
    return true
  }

  async function requestOtp(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!validateEmail()) return

    setPending("otp")
    const { error: authError } = await authClient.emailOtp.sendVerificationOtp({
      email: normalizedEmail,
      type: "sign-in",
    })
    setPending(null)

    if (authError) {
      setError(authError.message ?? "Could not send the code. Try again.")
      return
    }

    setStep("otp")
    toast.success("Code sent. Check your inbox.")
  }

  async function verifyOtp(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (otp.trim().length < 6) {
      setError("Enter the 6-digit code from the email.")
      return
    }

    setPending("verify")
    const { error: authError } = await authClient.signIn.emailOtp({
      email: normalizedEmail,
      otp: otp.trim(),
    })
    setPending(null)

    if (authError) {
      setError(authError.message ?? "That code is invalid or expired.")
      return
    }

    router.push("/dashboard")
    router.refresh()
  }

  async function sendMagicLink(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!validateEmail()) return

    setPending("link")
    const { error: authError } = await authClient.signIn.magicLink({
      email: normalizedEmail,
      callbackURL: "/dashboard",
      newUserCallbackURL: "/dashboard",
      errorCallbackURL: "/sign-in",
    })
    setPending(null)

    if (authError) {
      setError(authError.message ?? "Could not send the link. Try again.")
      return
    }

    setLinkSent(true)
  }

  async function signInWithGoogle() {
    setPending("google")
    setError(null)
    const { error: authError } = await authClient.signIn.social({
      provider: "google",
      callbackURL: "/dashboard",
      errorCallbackURL: "/sign-in",
    })
    if (authError) {
      setPending(null)
      setError(authError.message ?? "Google sign-in failed.")
    }
  }

  async function signInWithGithub() {
    setPending("github")
    setError(null)
    const { error: authError } = await authClient.signIn.social({
      provider: "github",
      callbackURL: "/dashboard",
      errorCallbackURL: "/sign-in",
    })
    if (authError) {
      setPending(null)
      setError(authError.message ?? "GitHub sign-in failed.")
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <Tabs
        defaultValue="code"
        onValueChange={() => {
          setError(null)
          setStep("email")
          setLinkSent(false)
        }}
      >
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="code">Email code</TabsTrigger>
          <TabsTrigger value="link">Magic link</TabsTrigger>
        </TabsList>

        <TabsContent value="code" className="pt-4">
          {step === "email" ? (
            <form onSubmit={requestOtp} noValidate>
              <FieldGroup>
                <Field data-invalid={Boolean(error)}>
                  <FieldLabel htmlFor="otp-email">Work email</FieldLabel>
                  <Input
                    id="otp-email"
                    type="email"
                    name="email"
                    autoComplete="email"
                    placeholder="you@company.com"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    aria-invalid={Boolean(error)}
                    required
                  />
                  <FieldDescription>We email a 6-digit code.</FieldDescription>
                  <FieldError>{error}</FieldError>
                </Field>
                <Button
                  type="submit"
                  disabled={pending !== null}
                  className="w-full"
                >
                  {pending === "otp" ? <Spinner /> : <PaperPlaneTiltIcon />}
                  Send sign-in code
                </Button>
              </FieldGroup>
            </form>
          ) : (
            <form onSubmit={verifyOtp} noValidate>
              <FieldGroup>
                <div className="flex items-center justify-between">
                  <p className="text-sm text-muted-foreground">
                    Sent to{" "}
                    <span className="font-medium text-foreground">
                      {normalizedEmail}
                    </span>
                  </p>
                  <Button
                    type="button"
                    variant="ghost"
                    size="xs"
                    onClick={() => {
                      setStep("email")
                      setOtp("")
                      setError(null)
                    }}
                  >
                    <ArrowLeftIcon />
                    Change
                  </Button>
                </div>
                <Field data-invalid={Boolean(error)}>
                  <FieldLabel htmlFor="otp-code">6-digit code</FieldLabel>
                  <Input
                    id="otp-code"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    pattern="[0-9]*"
                    maxLength={6}
                    placeholder="000000"
                    value={otp}
                    onChange={(event) =>
                      setOtp(event.target.value.replace(/\D/g, "").slice(0, 6))
                    }
                    className="h-12 text-center font-mono text-xl tracking-[0.4em]"
                    aria-invalid={Boolean(error)}
                    autoFocus
                    required
                  />
                  <FieldDescription>
                    Codes expire after 10 minutes and allow 5 attempts.
                  </FieldDescription>
                  <FieldError>{error}</FieldError>
                </Field>
                <Button
                  type="submit"
                  disabled={pending !== null}
                  className="w-full"
                >
                  {pending === "verify" ? <Spinner /> : null}
                  Verify and sign in
                </Button>
              </FieldGroup>
            </form>
          )}
        </TabsContent>

        <TabsContent value="link" className="pt-4">
          {linkSent ? (
            <div className="rounded-lg border border-border bg-muted/40 p-4 text-sm">
              <p className="font-medium">Check your inbox</p>
              <p className="mt-1 text-muted-foreground">
                A single-use sign-in link was sent to {normalizedEmail}. It
                expires in 15 minutes.
              </p>
              <Button
                variant="outline"
                size="sm"
                className="mt-4"
                onClick={() => setLinkSent(false)}
              >
                Send another link
              </Button>
            </div>
          ) : (
            <form onSubmit={sendMagicLink} noValidate>
              <FieldGroup>
                <Field data-invalid={Boolean(error)}>
                  <FieldLabel htmlFor="link-email">Work email</FieldLabel>
                  <Input
                    id="link-email"
                    type="email"
                    name="email"
                    autoComplete="email"
                    placeholder="you@company.com"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    aria-invalid={Boolean(error)}
                    required
                  />
                  <FieldDescription>
                    We email a one-click link. No password to remember.
                  </FieldDescription>
                  <FieldError>{error}</FieldError>
                </Field>
                <Button
                  type="submit"
                  disabled={pending !== null}
                  className="w-full"
                >
                  {pending === "link" ? <Spinner /> : <PaperPlaneTiltIcon />}
                  Email me a sign-in link
                </Button>
              </FieldGroup>
            </form>
          )}
        </TabsContent>
      </Tabs>

      <div className="flex items-center gap-3">
        <span className="h-px flex-1 bg-border" />
        <span className="font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
          or
        </span>
        <span className="h-px flex-1 bg-border" />
      </div>

      <div className="flex flex-col gap-2">
        <Button
          type="button"
          variant="outline"
          className="w-full"
          disabled={!googleEnabled || pending !== null}
          onClick={signInWithGoogle}
        >
          {pending === "google" ? <Spinner /> : <GoogleLogoIcon />}
          Continue with Google
        </Button>
        <Button
          type="button"
          variant="outline"
          className="w-full"
          disabled={!githubEnabled || pending !== null}
          onClick={signInWithGithub}
        >
          {pending === "github" ? <Spinner /> : <GithubLogoIcon />}
          Continue with GitHub
        </Button>
        {!googleEnabled && !githubEnabled ? (
          <p className="text-center text-xs text-muted-foreground">
            Social sign-in is not configured. Set Google or GitHub App OAuth
            credentials, or use an email method.
          </p>
        ) : (
          <>
            {!googleEnabled ? (
              <p className="text-center text-xs text-muted-foreground">
                Google sign-in is not configured on this deployment.
              </p>
            ) : null}
            {!githubEnabled ? (
              <p className="text-center text-xs text-muted-foreground">
                GitHub sign-in is not configured. Set GITHUB_APP_CLIENT_ID and
                GITHUB_APP_CLIENT_SECRET to enable it.
              </p>
            ) : null}
          </>
        )}
      </div>
    </div>
  )
}
