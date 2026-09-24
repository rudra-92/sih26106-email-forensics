"use client"

import { GlobePulse } from "@/components/ui/cobe-globe-pulse"

export default function GlobePulseDemo() {
  return (
    <div className="flex items-center justify-center w-full min-h-screen bg-black p-8 overflow-hidden">
      <div className="w-full max-w-lg">
        <GlobePulse />
      </div>
    </div>
  )
}
