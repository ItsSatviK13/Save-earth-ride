'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue
} from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger
} from '@/components/ui/dialog'
import {
  ExternalLink,
  Award,
  Star,
  Handshake,
  Bike,
  Building,
  Send,
  RefreshCw
} from 'lucide-react'
import { toast } from 'sonner'

/* ──────────────────────────────────────────────────────────
   Fallback / skeleton data (used only until API responds)
   ────────────────────────────────────────────────────────── */
const defaultSponsorsData = [
  {
    id: 1,
    name: 'EcoRide Motors',
    logo:
      'https://images.pexels.com/photos/1119796/pexels-photo-1119796.jpeg?auto=compress&cs=tinysrgb&w=200',
    tier: 'Platinum',
    website: 'https://ecoride.com',
    description:
      'Leading manufacturer of eco-friendly motorcycles and electric bikes. Committed to sustainable transportation solutions.',
    contribution:
      'Provides eco-friendly motorcycles for our rides and sponsors 1000 trees annually.',
    since: 2022,
    category: 'Automotive',
    type: 'sponsor'
  },
  {
    id: 2,
    name: 'GreenTech Solutions',
    logo:
      'https://images.pexels.com/photos/1416530/pexels-photo-1416530.jpeg?auto=compress&cs=tinysrgb&w=200',
    tier: 'Gold',
    website: 'https://greentech.com',
    description:
      'Technology company focused on environmental solutions and carbon-footprint reduction.',
    contribution:
      'Sponsors our mobile-app development and provides GPS tracking devices for rides.',
    since: 2023,
    category: 'Technology',
    type: 'sponsor'
  },
  {
    id: 3,
    name: 'Global Riders Alliance',
    logo:
      'https://images.pexels.com/photos/1005648/pexels-photo-1005648.jpeg?auto=compress&cs=tinysrgb&w=200',
    tier: '',
    website: 'https://globalriders.org',
    description:
      'International network of motorcycle clubs promoting responsible riding and environmental awareness.',
    contribution:
      'Strategic partnership for global event coordination and rider-network expansion.',
    since: 2022,
    category: 'Non-Profit',
    type: 'partner'
  }
]

/* ────────────────────────────────────────────────────────── */

export default function SponsorsPage() {
  /* -- data & loading state -- */
  const [sponsorsData, setSponsorsData] = useState(defaultSponsorsData)
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)

  /* -- dialog / form state -- */
  const [isPartnerFormOpen, setIsPartnerFormOpen] = useState(false)
  const [partnerForm, setPartnerForm] = useState({
    type: 'partner',            // sponsor | partner
    companyName: '',
    contactPerson: '',
    email: '',
    phone: '',
    website: '',
    category: '',
    description: '',
    contribution: '',
    proposedTier: '',
    message: ''
  })

  /* ─────────────────────  fetch helpers  ───────────────────── */
  const loadSponsorsData = async (showToast = false) => {
    try {
      if (showToast) setIsRefreshing(true)

      const res = await fetch('/api/sponsors', {
        method: 'GET',
        headers: { 'Cache-Control': 'no-cache', Pragma: 'no-cache' }
      })
      const json = await res.json()

      if (res.ok && json.success) {
        setSponsorsData(json.data)
        if (showToast) toast.success('Sponsors list refreshed')
      } else {
        throw new Error(json.error || 'Unknown response')
      }
    } catch (err) {
      console.error(err)
      if (showToast) toast.error('Failed to refresh sponsors list')
    } finally {
      setIsLoading(false)
      setIsRefreshing(false)
    }
  }

  /* first load */
  useEffect(() => { loadSponsorsData() }, [])

  /* auto-refresh every 30 s */
  useEffect(() => {
    const id = setInterval(loadSponsorsData, 30_000)
    return () => clearInterval(id)
  }, [])

  /* ───────────────────  computed arrays  ─────────────────── */
  const sponsors = sponsorsData.filter(s => s.type === 'sponsor')
  const partners = sponsorsData.filter(s => s.type === 'partner')

  /* ───────────────────  helpers (badge styles) ───────────── */
  const getTierColor = (tier: string) => {
    switch (tier) {
      case 'Platinum':
        return 'bg-gradient-to-r from-gray-300 to-gray-500 text-white'
      case 'Gold':
        return 'bg-gradient-to-r from-yellow-400 to-yellow-600 text-white'
      case 'Silver':
        return 'bg-gradient-to-r from-gray-400 to-gray-600 text-white'
      case 'Bronze':
        return 'bg-gradient-to-r from-orange-400 to-orange-600 text-white'
      default:
        return 'bg-gray-100 text-gray-800'
    }
  }
  const getTierIcon = (tier: string) => {
    switch (tier) {
      case 'Platinum':
        return <Award className="h-4 w-4" />
      case 'Gold':
        return <Star className="h-4 w-4" />
      case 'Silver':
        return <Bike className="h-4 w-4" />
      case 'Bronze':
        return <Building className="h-4 w-4" />
      default:
        return <Handshake className="h-4 w-4" />
    }
  }

  /* ──────────────────────────────────────────────────────────
     Partner / Sponsor application POST
     ────────────────────────────────────────────────────────── */
  const handlePartnerSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    const { companyName, contactPerson, email } = partnerForm
    if (!companyName || !contactPerson || !email) {
      toast.error('Please fill in company name, contact person and email')
      return
    }

    const payload = {
      action: 'add',
      data: {
        /* 10 required core fields */
        name: companyName,
        logo: '', // no logo yet
        tier: partnerForm.proposedTier,
        website: partnerForm.website,
        description: partnerForm.description,
        contribution: partnerForm.contribution,
        since: new Date().getFullYear(),
        category: partnerForm.category,
        type: partnerForm.type,
        id: 0, // server will assign

        /* three optional fields requested by the new schema */
        company_name: companyName,
        email: email,
        phone_number: partnerForm.phone
      }
    }

    try {
      const res = await fetch('/api/sponsors', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })
      const json = await res.json()

      if (!res.ok || !json.success) {
        throw new Error(json.error || 'Submission failed')
      }

      setSponsorsData(prev => [...prev, json.data])
      toast.success('Application submitted – thank you!')
      setIsPartnerFormOpen(false)
      setPartnerForm({
        type: 'partner',
        companyName: '',
        contactPerson: '',
        email: '',
        phone: '',
        website: '',
        category: '',
        description: '',
        contribution: '',
        proposedTier: '',
        message: ''
      })
    } catch (err: any) {
      console.error(err)
      toast.error(err.message || 'Could not submit application')
    }
  }

  /* ───────────────────  loading skeleton  ────────────────── */
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <RefreshCw className="h-8 w-8 animate-spin text-primary mr-3" />
        <span className="text-gray-600">Loading sponsors…</span>
      </div>
    )
  }

  /* ─────────────────────────  JSX  ───────────────────────── */
  return (
    <div className="min-h-screen bg-gray-50">
      {/* ── Hero Banner ────────────────────── */}
      <div className="relative py-20 overflow-hidden">
        <div
          className="absolute inset-0 bg-cover bg-center"
          style={{
            backgroundImage:
              'url(https://images.pexels.com/photos/2396045/pexels-photo-2396045.jpeg?auto=compress&cs=tinysrgb&w=1920)',
            filter: 'brightness(0.2)'
          }}
        />
        <div className="relative z-10 text-center text-white container mx-auto px-4">
          <Handshake className="h-12 w-12 mb-6 mx-auto" />
          <h1 className="text-5xl font-bold mb-6">Our Sponsors & Partners</h1>
          <p className="max-w-3xl mx-auto text-xl mb-8">
            We’re proud to collaborate with organisations that share our vision
            of environmental conservation and sustainable transportation.
          </p>

          <div className="flex items-center justify-center gap-4">
            <Button
              size="lg"
              className="bg-white text-green-600 hover:bg-gray-100"
              onClick={() => setIsPartnerFormOpen(true)}
            >
              <Handshake className="h-5 w-5 mr-2" />
              Become a Partner
            </Button>
            <Button
              size="lg"
              className="bg-white text-green-600 hover:bg-gray-100"
              onClick={() => loadSponsorsData(true)}
              disabled={isRefreshing}
            >
              <RefreshCw
                className={`h-5 w-5 mr-2 ${
                  isRefreshing ? 'animate-spin' : ''
                }`}
              />
              {isRefreshing ? 'Refreshing…' : 'Refresh'}
            </Button>
          </div>
        </div>
      </div>

      {/* ── Content ────────────────────────── */}
      <div className="container mx-auto px-4 py-12">

        {/* Sponsors ------------------------------------------------ */}
        <section className="mb-20">
          <header className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-2">Our Sponsors</h2>
            <p className="text-lg text-gray-600">
              Companies that fuel our mission with their generous support
            </p>
            <p className="text-sm text-gray-500 mt-2">
              Showing {sponsors.length} active sponsor
              {sponsors.length === 1 ? '' : 's'}
            </p>
          </header>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {sponsors.map(s => (
              <Dialog key={s.id}>
                <DialogTrigger asChild>
                  <Card className="cursor-pointer border-0 shadow-lg group relative overflow-hidden">
                    <div className="absolute inset-0 bg-gradient-to-br from-green-400/10 to-blue-400/10 opacity-0 group-hover:opacity-100 transition-opacity" />
                    <CardContent className="p-6 relative z-10">
                      <div className="text-center space-y-4">
                        <div className="relative w-fit mx-auto">
                          <img
                            src={s.logo}
                            alt={s.name}
                            className="w-20 h-20 rounded-full object-cover border-4 border-white shadow-lg"
                          />
                          {s.tier && (
                            <div className="absolute -top-2 -right-2">
                              <Badge
                                className={`${getTierColor(
                                  s.tier
                                )} text-xs px-2 py-1`}
                              >
                                {getTierIcon(s.tier)}
                                <span className="ml-1">{s.tier}</span>
                              </Badge>
                            </div>
                          )}
                        </div>
                        <h3 className="text-xl font-bold">{s.name}</h3>
                        <Badge variant="outline" className="text-xs">
                          {s.category}
                        </Badge>
                        <p className="text-sm text-gray-600 line-clamp-3">
                          {s.description}
                        </p>
                        <div className="text-xs text-gray-500">
                          Partner since {s.since}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </DialogTrigger>

                <DialogContent className="max-w-2xl">
                  <DialogHeader>
                    <DialogTitle className="flex items-center gap-3">
                      <img
                        src={s.logo}
                        alt={s.name}
                        className="w-12 h-12 rounded-full object-cover"
                      />
                      <div>
                        <div className="flex items-center gap-2">
                          <span>{s.name}</span>
                          {s.tier && (
                            <Badge
                              className={`${getTierColor(s.tier)} text-xs`}
                            >
                              {getTierIcon(s.tier)}
                              <span className="ml-1">{s.tier}</span>
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm text-gray-500">
                          {s.category} • Since {s.since}
                        </p>
                      </div>
                    </DialogTitle>
                  </DialogHeader>

                  <div className="space-y-4">
                    <section>
                      <h4 className="font-semibold mb-2">About</h4>
                      <p className="text-gray-600">{s.description}</p>
                    </section>
                    <section>
                      <h4 className="font-semibold mb-2">Contribution</h4>
                      <p className="text-gray-600">{s.contribution}</p>
                    </section>
                    {s.website && (
                      <div className="pt-4">
                        <Button asChild>
                          <a
                            href={s.website}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            <ExternalLink className="h-4 w-4 mr-2" />
                            Visit Website
                          </a>
                        </Button>
                      </div>
                    )}
                  </div>
                </DialogContent>
              </Dialog>
            ))}
          </div>
        </section>

        {/* Partners ------------------------------------------------ */}
        <section className="mb-16">
          <header className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-2">Strategic Partners</h2>
            <p className="text-lg text-gray-600">
              Organisations we collaborate with to amplify our impact
            </p>
            <p className="text-sm text-gray-500 mt-2">
              Showing {partners.length} active partner
              {partners.length === 1 ? '' : 's'}
            </p>
          </header>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {partners.map(p => (
              <Dialog key={p.id}>
                <DialogTrigger asChild>
                  <Card className="cursor-pointer border-0 shadow-lg group">
                    <CardContent className="p-6">
                      <div className="text-center space-y-4">
                        <img
                          src={p.logo}
                          alt={p.name}
                          className="w-16 h-16 mx-auto rounded-full border-2 border-gray-200 object-cover"
                        />
                        <h3 className="text-lg font-semibold group-hover:text-primary">
                          {p.name}
                        </h3>
                        <Badge variant="outline" className="text-xs">
                          {p.category}
                        </Badge>
                        <p className="text-sm text-gray-600 line-clamp-3">
                          {p.description}
                        </p>
                        <div className="text-xs text-gray-500">
                          Since {p.since}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </DialogTrigger>

                <DialogContent>
                  <DialogHeader>
                    <DialogTitle className="flex items-center gap-3">
                      <img
                        src={p.logo}
                        alt={p.name}
                        className="w-10 h-10 rounded-full object-cover"
                      />
                      <div>
                        <div>{p.name}</div>
                        <p className="text-sm text-gray-500">
                          Partner since {p.since}
                        </p>
                      </div>
                    </DialogTitle>
                  </DialogHeader>

                  <div className="space-y-4">
                    <section>
                      <h4 className="font-semibold mb-2">About</h4>
                      <p className="text-gray-600">{p.description}</p>
                    </section>
                    <section>
                      <h4 className="font-semibold mb-2">Partnership</h4>
                      <p className="text-gray-600">{p.contribution}</p>
                    </section>
                    {p.website && (
                      <div className="pt-4">
                        <Button asChild variant="outline">
                          <a
                            href={p.website}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            <ExternalLink className="h-4 w-4 mr-2" />
                            Visit Website
                          </a>
                        </Button>
                      </div>
                    )}
                  </div>
                </DialogContent>
              </Dialog>
            ))}
          </div>
        </section>
      </div>

      {/* ── Partner / Sponsor Application Dialog ───────────── */}
      <Dialog open={isPartnerFormOpen} onOpenChange={setIsPartnerFormOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Building className="h-6 w-6 text-primary" />
              Partnership Application
            </DialogTitle>
          </DialogHeader>

          <form onSubmit={handlePartnerSubmit} className="space-y-6">
            <div className="grid grid-cols-2 gap-4">
              {/* partnership type */}
              <div>
                <Label>Partnership Type *</Label>
                <Select
                  value={partnerForm.type}
                  onValueChange={v =>
                    setPartnerForm(f => ({ ...f, type: v }))
                  }
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="sponsor">Sponsor</SelectItem>
                    <SelectItem value="partner">Strategic Partner</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* company name */}
              <div>
                <Label>Company / Organisation Name *</Label>
                <Input
                  value={partnerForm.companyName}
                  onChange={e =>
                    setPartnerForm(f => ({
                      ...f,
                      companyName: e.target.value
                    }))
                  }
                  required
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              {/* contact person */}
              <div>
                <Label>Contact Person *</Label>
                <Input
                  value={partnerForm.contactPerson}
                  onChange={e =>
                    setPartnerForm(f => ({
                      ...f,
                      contactPerson: e.target.value
                    }))
                  }
                  required
                />
              </div>

              {/* email */}
              <div>
                <Label>Email Address *</Label>
                <Input
                  type="email"
                  value={partnerForm.email}
                  onChange={e =>
                    setPartnerForm(f => ({ ...f, email: e.target.value }))
                  }
                  required
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              {/* phone */}
              <div>
                <Label>Phone Number</Label>
                <Input
                  value={partnerForm.phone}
                  onChange={e =>
                    setPartnerForm(f => ({ ...f, phone: e.target.value }))
                  }
                />
              </div>

              {/* website */}
              <div>
                <Label>Website</Label>
                <Input
                  value={partnerForm.website}
                  onChange={e =>
                    setPartnerForm(f => ({ ...f, website: e.target.value }))
                  }
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              {/* industry category */}
              <div>
                <Label>Industry / Category</Label>
                <Select
                  value={partnerForm.category}
                  onValueChange={v =>
                    setPartnerForm(f => ({ ...f, category: v }))
                  }
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select category" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="Automotive">Automotive</SelectItem>
                    <SelectItem value="Technology">Technology</SelectItem>
                    <SelectItem value="Energy">Energy</SelectItem>
                    <SelectItem value="Finance">Finance</SelectItem>
                    <SelectItem value="Healthcare">Healthcare</SelectItem>
                    <SelectItem value="Non-Profit">Non-Profit</SelectItem>
                    <SelectItem value="Other">Other</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* proposed tier (only if sponsor) */}
              {partnerForm.type === 'sponsor' && (
                <div>
                  <Label>Proposed Sponsorship Tier</Label>
                  <Select
                    value={partnerForm.proposedTier}
                    onValueChange={v =>
                      setPartnerForm(f => ({ ...f, proposedTier: v }))
                    }
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select tier" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Platinum">Platinum</SelectItem>
                      <SelectItem value="Gold">Gold</SelectItem>
                      <SelectItem value="Silver">Silver</SelectItem>
                      <SelectItem value="Bronze">Bronze</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              )}
            </div>

            <div>
              <Label>Company Description</Label>
              <Textarea
                rows={3}
                value={partnerForm.description}
                onChange={e =>
                  setPartnerForm(f => ({ ...f, description: e.target.value }))
                }
              />
            </div>

            <div>
              <Label>Proposed Contribution</Label>
              <Textarea
                rows={3}
                value={partnerForm.contribution}
                onChange={e =>
                  setPartnerForm(f => ({ ...f, contribution: e.target.value }))
                }
              />
            </div>

            <div>
              <Label>Additional Message</Label>
              <Textarea
                rows={2}
                value={partnerForm.message}
                onChange={e =>
                  setPartnerForm(f => ({ ...f, message: e.target.value }))
                }
              />
            </div>

            <div className="flex justify-end gap-3">
              <Button
                type="button"
                variant="outline"
                onClick={() => setIsPartnerFormOpen(false)}
              >
                Cancel
              </Button>
              <Button type="submit">
                <Send className="h-4 w-4 mr-2" />
                Submit Application
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}