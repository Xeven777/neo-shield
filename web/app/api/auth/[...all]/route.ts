import { toNextJsHandler } from "better-auth/next-js"

import { getAuth } from "@/lib/auth/auth"

export const dynamic = "force-dynamic"

const handler = toNextJsHandler((request) => getAuth().handler(request))

export async function GET(request: Request) {
  return handler.GET(request)
}

export async function POST(request: Request) {
  return handler.POST(request)
}
