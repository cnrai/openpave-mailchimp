#!/usr/bin/env node

/**
 * Mailchimp CLI - PAVE Secure Token Version
 * 
 * Access Mailchimp Marketing API using secure token system.
 * Tokens are never visible to sandbox code - they're injected by the host.
 * 
 * Token configuration in ~/.pave/permissions.yaml:
 * 
 * tokens:
 *   mailchimp:
 *     env: MAILCHIMP_API_KEY
 *     type: api_key
 *     domains:
 *       - "*.api.mailchimp.com"
 *     placement:
 *       type: header
 *       name: Authorization
 *       format: "Bearer {token}"
 */

// Constants - will be set after detecting datacenter
let MAILCHIMP_BASE_URL = null;

/**
 * URL encoding function for sandbox compatibility (no URLSearchParams)
 */
function encodeFormData(data) {
  const params = [];
  for (const [key, value] of Object.entries(data)) {
    if (value !== undefined && value !== null && value !== '') {
      params.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
    }
  }
  return params.join('&');
}

/**
 * Simple MD5 implementation for email hashing
 * Mailchimp requires MD5 hash of lowercase email for member lookups
 */
function md5(str) {
  // Simple MD5 implementation for sandbox environment
  function rotateLeft(n, s) {
    return (n << s) | (n >>> (32 - s));
  }
  
  function addUnsigned(x, y) {
    const x4 = x & 0x80000000;
    const y4 = y & 0x80000000;
    const x8 = x & 0x40000000;
    const y8 = y & 0x40000000;
    const result = (x & 0x3FFFFFFF) + (y & 0x3FFFFFFF);
    if (x8 & y8) return result ^ 0x80000000 ^ x4 ^ y4;
    if (x8 | y8) {
      if (result & 0x40000000) return result ^ 0xC0000000 ^ x4 ^ y4;
      return result ^ 0x40000000 ^ x4 ^ y4;
    }
    return result ^ x4 ^ y4;
  }
  
  function F(x, y, z) { return (x & y) | (~x & z); }
  function G(x, y, z) { return (x & z) | (y & ~z); }
  function H(x, y, z) { return x ^ y ^ z; }
  function I(x, y, z) { return y ^ (x | ~z); }
  
  function FF(a, b, c, d, x, s, ac) {
    a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function GG(a, b, c, d, x, s, ac) {
    a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function HH(a, b, c, d, x, s, ac) {
    a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function II(a, b, c, d, x, s, ac) {
    a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  
  function convertToWordArray(str) {
    let lWordCount;
    const lMessageLength = str.length;
    const lNumberOfWords_temp1 = lMessageLength + 8;
    const lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
    const lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
    const lWordArray = Array(lNumberOfWords - 1);
    let lBytePosition = 0;
    let lByteCount = 0;
    while (lByteCount < lMessageLength) {
      lWordCount = (lByteCount - (lByteCount % 4)) / 4;
      lBytePosition = (lByteCount % 4) * 8;
      lWordArray[lWordCount] = (lWordArray[lWordCount] | (str.charCodeAt(lByteCount) << lBytePosition));
      lByteCount++;
    }
    lWordCount = (lByteCount - (lByteCount % 4)) / 4;
    lBytePosition = (lByteCount % 4) * 8;
    lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
    lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
    lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
    return lWordArray;
  }
  
  function wordToHex(lValue) {
    let result = '';
    for (let i = 0; i <= 3; i++) {
      const byte = (lValue >>> (i * 8)) & 255;
      result += ('0' + byte.toString(16)).slice(-2);
    }
    return result;
  }
  
  const x = convertToWordArray(str);
  let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
  
  const S11 = 7, S12 = 12, S13 = 17, S14 = 22;
  const S21 = 5, S22 = 9, S23 = 14, S24 = 20;
  const S31 = 4, S32 = 11, S33 = 16, S34 = 23;
  const S41 = 6, S42 = 10, S43 = 15, S44 = 21;
  
  for (let k = 0; k < x.length; k += 16) {
    const AA = a, BB = b, CC = c, DD = d;
    a = FF(a, b, c, d, x[k+0], S11, 0xD76AA478);
    d = FF(d, a, b, c, x[k+1], S12, 0xE8C7B756);
    c = FF(c, d, a, b, x[k+2], S13, 0x242070DB);
    b = FF(b, c, d, a, x[k+3], S14, 0xC1BDCEEE);
    a = FF(a, b, c, d, x[k+4], S11, 0xF57C0FAF);
    d = FF(d, a, b, c, x[k+5], S12, 0x4787C62A);
    c = FF(c, d, a, b, x[k+6], S13, 0xA8304613);
    b = FF(b, c, d, a, x[k+7], S14, 0xFD469501);
    a = FF(a, b, c, d, x[k+8], S11, 0x698098D8);
    d = FF(d, a, b, c, x[k+9], S12, 0x8B44F7AF);
    c = FF(c, d, a, b, x[k+10], S13, 0xFFFF5BB1);
    b = FF(b, c, d, a, x[k+11], S14, 0x895CD7BE);
    a = FF(a, b, c, d, x[k+12], S11, 0x6B901122);
    d = FF(d, a, b, c, x[k+13], S12, 0xFD987193);
    c = FF(c, d, a, b, x[k+14], S13, 0xA679438E);
    b = FF(b, c, d, a, x[k+15], S14, 0x49B40821);
    a = GG(a, b, c, d, x[k+1], S21, 0xF61E2562);
    d = GG(d, a, b, c, x[k+6], S22, 0xC040B340);
    c = GG(c, d, a, b, x[k+11], S23, 0x265E5A51);
    b = GG(b, c, d, a, x[k+0], S24, 0xE9B6C7AA);
    a = GG(a, b, c, d, x[k+5], S21, 0xD62F105D);
    d = GG(d, a, b, c, x[k+10], S22, 0x02441453);
    c = GG(c, d, a, b, x[k+15], S23, 0xD8A1E681);
    b = GG(b, c, d, a, x[k+4], S24, 0xE7D3FBC8);
    a = GG(a, b, c, d, x[k+9], S21, 0x21E1CDE6);
    d = GG(d, a, b, c, x[k+14], S22, 0xC33707D6);
    c = GG(c, d, a, b, x[k+3], S23, 0xF4D50D87);
    b = GG(b, c, d, a, x[k+8], S24, 0x455A14ED);
    a = GG(a, b, c, d, x[k+13], S21, 0xA9E3E905);
    d = GG(d, a, b, c, x[k+2], S22, 0xFCEFA3F8);
    c = GG(c, d, a, b, x[k+7], S23, 0x676F02D9);
    b = GG(b, c, d, a, x[k+12], S24, 0x8D2A4C8A);
    a = HH(a, b, c, d, x[k+5], S31, 0xFFFA3942);
    d = HH(d, a, b, c, x[k+8], S32, 0x8771F681);
    c = HH(c, d, a, b, x[k+11], S33, 0x6D9D6122);
    b = HH(b, c, d, a, x[k+14], S34, 0xFDE5380C);
    a = HH(a, b, c, d, x[k+1], S31, 0xA4BEEA44);
    d = HH(d, a, b, c, x[k+4], S32, 0x4BDECFA9);
    c = HH(c, d, a, b, x[k+7], S33, 0xF6BB4B60);
    b = HH(b, c, d, a, x[k+10], S34, 0xBEBFBC70);
    a = HH(a, b, c, d, x[k+13], S31, 0x289B7EC6);
    d = HH(d, a, b, c, x[k+0], S32, 0xEAA127FA);
    c = HH(c, d, a, b, x[k+3], S33, 0xD4EF3085);
    b = HH(b, c, d, a, x[k+6], S34, 0x04881D05);
    a = HH(a, b, c, d, x[k+9], S31, 0xD9D4D039);
    d = HH(d, a, b, c, x[k+12], S32, 0xE6DB99E5);
    c = HH(c, d, a, b, x[k+15], S33, 0x1FA27CF8);
    b = HH(b, c, d, a, x[k+2], S34, 0xC4AC5665);
    a = II(a, b, c, d, x[k+0], S41, 0xF4292244);
    d = II(d, a, b, c, x[k+7], S42, 0x432AFF97);
    c = II(c, d, a, b, x[k+14], S43, 0xAB9423A7);
    b = II(b, c, d, a, x[k+5], S44, 0xFC93A039);
    a = II(a, b, c, d, x[k+12], S41, 0x655B59C3);
    d = II(d, a, b, c, x[k+3], S42, 0x8F0CCC92);
    c = II(c, d, a, b, x[k+10], S43, 0xFFEFF47D);
    b = II(b, c, d, a, x[k+1], S44, 0x85845DD1);
    a = II(a, b, c, d, x[k+8], S41, 0x6FA87E4F);
    d = II(d, a, b, c, x[k+15], S42, 0xFE2CE6E0);
    c = II(c, d, a, b, x[k+6], S43, 0xA3014314);
    b = II(b, c, d, a, x[k+13], S44, 0x4E0811A1);
    a = II(a, b, c, d, x[k+4], S41, 0xF7537E82);
    d = II(d, a, b, c, x[k+11], S42, 0xBD3AF235);
    c = II(c, d, a, b, x[k+2], S43, 0x2AD7D2BB);
    b = II(b, c, d, a, x[k+9], S44, 0xEB86D391);
    a = addUnsigned(a, AA);
    b = addUnsigned(b, BB);
    c = addUnsigned(c, CC);
    d = addUnsigned(d, DD);
  }
  
  return wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d);
}

/**
 * Print token configuration error
 */
function printTokenError() {
  console.error('Mailchimp token not configured.');
  console.error('');
  console.error('Add to ~/.pave/permissions.yaml under tokens section:');
  console.error('');
  console.error('tokens:');
  console.error('  mailchimp:');
  console.error('    env: MAILCHIMP_API_KEY');
  console.error('    type: api_key');
  console.error('    domains:');
  console.error('      - "*.api.mailchimp.com"');
  console.error('    placement:');
  console.error('      type: header');
  console.error('      name: Authorization');
  console.error('      format: "Bearer {token}"');
  console.error('');
  console.error('Then add your API key to ~/.pave/tokens.yaml:');
  console.error('');
  console.error('MAILCHIMP_API_KEY: "your-api-key-us21"');
  console.error('');
  console.error('Note: The API key format is: key-datacenter (e.g., abc123-us21)');
}

/**
 * Mailchimp API Client - Secure Token Version
 */
class MailchimpClient {
  constructor(datacenter) {
    // Check if mailchimp token is available via secure token system
    if (typeof hasToken === 'function' && !hasToken('mailchimp')) {
      printTokenError();
      throw new Error('Mailchimp token not configured');
    }

    this.datacenter = datacenter;
    this.baseUrl = `https://${datacenter}.api.mailchimp.com/3.0`;
  }

  /**
   * Make an authenticated request to the Mailchimp API
   */
  request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;

    const response = authenticatedFetch('mailchimp', url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      timeout: options.timeout || 30000
    });

    if (!response.ok) {
      let errorData;
      try {
        errorData = response.json();
      } catch (e) {
        errorData = { detail: response.text() };
      }
      const err = new Error(errorData.detail || errorData.title || `HTTP ${response.status}`);
      err.status = response.status;
      err.type = errorData.type;
      err.data = errorData;
      throw err;
    }

    return response.json();
  }

  // ==================== Account ====================

  /**
   * Get account info (ping/verify API key)
   */
  getAccountInfo() {
    return this.request('/');
  }

  // ==================== Lists/Audiences ====================

  /**
   * Get all lists/audiences
   */
  getLists(options = {}) {
    const params = {};
    if (options.count) params.count = options.count;
    if (options.offset) params.offset = options.offset;

    const queryString = encodeFormData(params);
    return this.request(`/lists${queryString ? `?${queryString}` : ''}`);
  }

  /**
   * Get a specific list/audience
   */
  getList(listId) {
    return this.request(`/lists/${listId}`);
  }

  // ==================== Members/Subscribers ====================

  /**
   * Get members of a list
   */
  getMembers(listId, options = {}) {
    const params = {};
    if (options.count) params.count = options.count;
    if (options.offset) params.offset = options.offset;
    if (options.status) params.status = options.status;
    if (options.since) params.since_timestamp_opt = options.since;

    const queryString = encodeFormData(params);
    return this.request(`/lists/${listId}/members${queryString ? `?${queryString}` : ''}`);
  }

  /**
   * Get a specific member by email
   */
  getMember(listId, email) {
    const subscriberHash = md5(email.toLowerCase());
    return this.request(`/lists/${listId}/members/${subscriberHash}`);
  }

  /**
   * Add a new member to a list
   */
  addMember(listId, memberData) {
    const body = {
      email_address: memberData.email,
      status: memberData.status || 'subscribed',
    };

    if (memberData.mergeFields) {
      body.merge_fields = memberData.mergeFields;
    }
    if (memberData.tags) {
      body.tags = memberData.tags;
    }

    return this.request(`/lists/${listId}/members`, {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  /**
   * Search members across all lists
   */
  searchMembers(query) {
    return this.request(`/search-members?query=${encodeURIComponent(query)}`);
  }

  // ==================== Campaigns ====================

  /**
   * Get all campaigns
   */
  getCampaigns(options = {}) {
    const params = {};
    if (options.count) params.count = options.count;
    if (options.offset) params.offset = options.offset;
    if (options.status) params.status = options.status;
    if (options.type) params.type = options.type;
    if (options.since) params.since_create_time = options.since;
    if (options.before) params.before_create_time = options.before;

    const queryString = encodeFormData(params);
    return this.request(`/campaigns${queryString ? `?${queryString}` : ''}`);
  }

  /**
   * Get a specific campaign
   */
  getCampaign(campaignId) {
    return this.request(`/campaigns/${campaignId}`);
  }

  /**
   * Get campaign content
   */
  getCampaignContent(campaignId) {
    return this.request(`/campaigns/${campaignId}/content`);
  }

  // ==================== Reports ====================

  /**
   * Get a specific campaign report
   */
  getCampaignReport(campaignId) {
    return this.request(`/reports/${campaignId}`);
  }

  /**
   * Get campaign click details
   */
  getCampaignClickDetails(campaignId) {
    return this.request(`/reports/${campaignId}/click-details`);
  }

  /**
   * Get campaign open details
   */
  getCampaignOpenDetails(campaignId, options = {}) {
    const params = {};
    if (options.count) params.count = options.count;
    if (options.offset) params.offset = options.offset;

    const queryString = encodeFormData(params);
    return this.request(`/reports/${campaignId}/open-details${queryString ? `?${queryString}` : ''}`);
  }

  // ==================== Tags ====================

  /**
   * Get tags for a list
   */
  getTags(listId) {
    return this.request(`/lists/${listId}/segments?type=static`);
  }

  // ==================== Automations ====================

  /**
   * Get all automations
   */
  getAutomations() {
    return this.request('/automations');
  }

  // ==================== Formatters ====================

  /**
   * Format member for display
   */
  static formatMember(member) {
    return {
      id: member.id,
      email: member.email_address,
      status: member.status,
      fullName: `${member.merge_fields?.FNAME || ''} ${member.merge_fields?.LNAME || ''}`.trim() || null,
      firstName: member.merge_fields?.FNAME || null,
      lastName: member.merge_fields?.LNAME || null,
      mergeFields: member.merge_fields || {},
      tags: member.tags?.map(t => t.name) || [],
      subscribed: member.timestamp_opt,
      lastChanged: member.last_changed,
      source: member.source,
      listId: member.list_id,
    };
  }

  /**
   * Format campaign for display
   */
  static formatCampaign(campaign) {
    return {
      id: campaign.id,
      webId: campaign.web_id,
      type: campaign.type,
      status: campaign.status,
      title: campaign.settings?.title || '(no title)',
      subject: campaign.settings?.subject_line || '(no subject)',
      previewText: campaign.settings?.preview_text || null,
      fromName: campaign.settings?.from_name,
      replyTo: campaign.settings?.reply_to,
      listId: campaign.recipients?.list_id,
      listName: campaign.recipients?.list_name,
      sendTime: campaign.send_time,
      createTime: campaign.create_time,
      emailsSent: campaign.emails_sent || 0,
      opens: campaign.report_summary?.opens || 0,
      uniqueOpens: campaign.report_summary?.unique_opens || 0,
      openRate: campaign.report_summary?.open_rate || 0,
      clicks: campaign.report_summary?.clicks || 0,
      subscriberClicks: campaign.report_summary?.subscriber_clicks || 0,
      clickRate: campaign.report_summary?.click_rate || 0,
    };
  }

  /**
   * Format list for display
   */
  static formatList(list) {
    return {
      id: list.id,
      webId: list.web_id,
      name: list.name,
      contact: list.contact,
      memberCount: list.stats?.member_count || 0,
      unsubscribeCount: list.stats?.unsubscribe_count || 0,
      cleanedCount: list.stats?.cleaned_count || 0,
      campaignCount: list.stats?.campaign_count || 0,
      lastSub: list.stats?.last_sub_date,
      lastUnsub: list.stats?.last_unsub_date,
      lastCampaign: list.stats?.campaign_last_sent,
      openRate: list.stats?.open_rate || 0,
      clickRate: list.stats?.click_rate || 0,
      dateCreated: list.date_created,
    };
  }
}

/**
 * Parse command line arguments
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const parsed = {
    command: null,
    positional: [],
    options: {}
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const [key, value] = arg.slice(2).split('=', 2);
      if (value !== undefined) {
        parsed.options[key] = value;
      } else if (i + 1 < args.length && !args[i + 1].startsWith('-')) {
        parsed.options[key] = args[i + 1];
        i++;
      } else {
        parsed.options[key] = true;
      }
    } else if (arg.startsWith('-')) {
      const flag = arg.slice(1);
      if (i + 1 < args.length && !args[i + 1].startsWith('-')) {
        parsed.options[flag] = args[i + 1];
        i++;
      } else {
        parsed.options[flag] = true;
      }
    } else {
      if (parsed.command === null) {
        parsed.command = arg;
      } else {
        parsed.positional.push(arg);
      }
    }
  }

  return parsed;
}

/**
 * Print help message
 */
function printHelp() {
  console.log(`
Mailchimp CLI - PAVE Secure Token Version

USAGE:
  mailchimp <command> [options]

COMMANDS:
  ping                           Verify API key and get account info
  lists                          List all audiences/lists
  list <listId>                  Get a specific list/audience details
  members <listId>               List members/subscribers of a list
  member <listId> <email>        Get a specific member by email
  add-member <listId> <email>    Add a new member to a list
  search <query>                 Search members across all lists
  campaigns                      List campaigns
  campaign <campaignId>          Get a specific campaign
  report <campaignId>            Get campaign report/analytics
  tags <listId>                  List tags for a list
  automations                    List all automations

OPTIONS:
  --dc <datacenter>              Mailchimp datacenter (e.g., us21) [required]
  --json                         Raw JSON output
  --summary                      Human-readable summary (default)

LIST/MEMBER OPTIONS:
  -n, --count <number>           Number of records to return (default: 10)
  --offset <number>              Number of records to skip (default: 0)
  -s, --status <status>          Filter by status

MEMBER STATUS VALUES:
  subscribed, unsubscribed, cleaned, pending, transactional

CAMPAIGN OPTIONS:
  -s, --status <status>          Filter by status: save, paused, schedule, sending, sent
  -t, --type <type>              Filter by type: regular, plaintext, absplit, rss, variate
  --since <date>                 Filter by create date (ISO 8601)
  --before <date>                Filter by create date (ISO 8601)
  --content                      Include campaign content (HTML)

ADD-MEMBER OPTIONS:
  -s, --status <status>          Status: subscribed, unsubscribed, pending (default: subscribed)
  --fname <name>                 First name
  --lname <name>                 Last name
  --tags <tags>                  Tags (comma-separated)

REPORT OPTIONS:
  --clicks                       Include click details
  --opens                        Include open details

EXAMPLES:
  mailchimp ping --dc us21 --summary
  mailchimp lists --dc us21 --summary
  mailchimp list b4cd77f0a4 --dc us21 --summary
  mailchimp members b4cd77f0a4 --dc us21 --count 20 --status subscribed
  mailchimp member b4cd77f0a4 user@example.com --dc us21 --summary
  mailchimp add-member b4cd77f0a4 new@example.com --dc us21 --fname John --lname Doe
  mailchimp search "john@example.com" --dc us21 --summary
  mailchimp campaigns --dc us21 --status sent --count 10 --summary
  mailchimp campaign abc123 --dc us21 --content --summary
  mailchimp report abc123 --dc us21 --clicks --opens --summary
  mailchimp tags b4cd77f0a4 --dc us21 --summary
  mailchimp automations --dc us21 --summary

TOKEN SETUP:
  Requires MAILCHIMP_API_KEY environment variable.
  API key format: key-datacenter (e.g., abc123def456-us21)
  Token is automatically injected via PAVE secure token system.
`);
}

/**
 * Main CLI execution
 */
function main() {
  const parsed = parseArgs();

  if (!parsed.command || parsed.command === 'help' || parsed.options.help) {
    printHelp();
    return;
  }

  // Datacenter is required
  const datacenter = parsed.options.dc;
  if (!datacenter) {
    console.error('Error: --dc <datacenter> is required (e.g., --dc us21)');
    console.error('');
    console.error('The datacenter is the last part of your API key (after the hyphen).');
    console.error('Example: If your API key is "abc123-us21", use --dc us21');
    process.exit(1);
  }

  try {
    const client = new MailchimpClient(datacenter);

    switch (parsed.command) {
      case 'ping': {
        const result = client.getAccountInfo();

        if (parsed.options.summary) {
          console.log(`Account: ${result.account_name}`);
          console.log(`Email: ${result.email}`);
          console.log(`Role: ${result.role}`);
          console.log(`Industry: ${result.industry_stats?.industry || 'N/A'}`);
          console.log(`Total Subscribers: ${result.total_subscribers}`);
        } else {
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }

      case 'lists': {
        const result = client.getLists({
          count: parseInt(parsed.options.count || parsed.options.n || '10'),
          offset: parseInt(parsed.options.offset || '0'),
        });

        if (parsed.options.summary) {
          console.log(`Found ${result.total_items} list(s):\n`);
          for (const list of result.lists) {
            const formatted = MailchimpClient.formatList(list);
            console.log(`${formatted.name}`);
            console.log(`  ID: ${formatted.id}`);
            console.log(`  Members: ${formatted.memberCount} (${formatted.unsubscribeCount} unsub, ${formatted.cleanedCount} cleaned)`);
            console.log(`  Open Rate: ${(formatted.openRate * 100).toFixed(1)}% | Click Rate: ${(formatted.clickRate * 100).toFixed(1)}%`);
            console.log(`  Campaigns: ${formatted.campaignCount}`);
            console.log('');
          }
        } else {
          const formatted = result.lists.map(l => MailchimpClient.formatList(l));
          console.log(JSON.stringify({ lists: formatted, total: result.total_items }, null, 2));
        }
        break;
      }

      case 'list': {
        const listId = parsed.positional[0];
        if (!listId) {
          console.error('Error: List ID required');
          console.error('Usage: mailchimp list <listId> --dc <dc>');
          process.exit(1);
        }

        const result = client.getList(listId);

        if (parsed.options.summary) {
          const formatted = MailchimpClient.formatList(result);
          console.log(`List: ${formatted.name}`);
          console.log(`ID: ${formatted.id}`);
          console.log(`Members: ${formatted.memberCount}`);
          console.log(`Unsubscribed: ${formatted.unsubscribeCount}`);
          console.log(`Cleaned: ${formatted.cleanedCount}`);
          console.log(`Campaigns Sent: ${formatted.campaignCount}`);
          console.log(`Open Rate: ${(formatted.openRate * 100).toFixed(1)}%`);
          console.log(`Click Rate: ${(formatted.clickRate * 100).toFixed(1)}%`);
          console.log(`Created: ${formatted.dateCreated}`);
        } else {
          console.log(JSON.stringify(MailchimpClient.formatList(result), null, 2));
        }
        break;
      }

      case 'members': {
        const listId = parsed.positional[0];
        if (!listId) {
          console.error('Error: List ID required');
          console.error('Usage: mailchimp members <listId> --dc <dc>');
          process.exit(1);
        }

        const result = client.getMembers(listId, {
          count: parseInt(parsed.options.count || parsed.options.n || '10'),
          offset: parseInt(parsed.options.offset || '0'),
          status: parsed.options.status || parsed.options.s,
          since: parsed.options.since,
        });

        if (parsed.options.summary) {
          console.log(`Found ${result.total_items} member(s):\n`);
          for (const member of result.members) {
            const formatted = MailchimpClient.formatMember(member);
            const name = formatted.fullName || '(no name)';
            const tags = formatted.tags.length > 0 ? ` [${formatted.tags.join(', ')}]` : '';
            console.log(`${formatted.email} - ${name}${tags}`);
            console.log(`  Status: ${formatted.status} | Subscribed: ${formatted.subscribed || 'N/A'}`);
          }
        } else {
          const formatted = result.members.map(m => MailchimpClient.formatMember(m));
          console.log(JSON.stringify({ members: formatted, total: result.total_items }, null, 2));
        }
        break;
      }

      case 'member': {
        const listId = parsed.positional[0];
        const email = parsed.positional[1];
        if (!listId || !email) {
          console.error('Error: List ID and email required');
          console.error('Usage: mailchimp member <listId> <email> --dc <dc>');
          process.exit(1);
        }

        const result = client.getMember(listId, email);

        if (parsed.options.summary) {
          const formatted = MailchimpClient.formatMember(result);
          console.log(`Email: ${formatted.email}`);
          console.log(`Name: ${formatted.fullName || '(no name)'}`);
          console.log(`Status: ${formatted.status}`);
          console.log(`Tags: ${formatted.tags.join(', ') || '(none)'}`);
          console.log(`Subscribed: ${formatted.subscribed || 'N/A'}`);
          console.log(`Last Changed: ${formatted.lastChanged || 'N/A'}`);
          console.log(`Source: ${formatted.source || 'N/A'}`);
          if (Object.keys(formatted.mergeFields).length > 0) {
            console.log(`Merge Fields: ${JSON.stringify(formatted.mergeFields)}`);
          }
        } else {
          console.log(JSON.stringify(MailchimpClient.formatMember(result), null, 2));
        }
        break;
      }

      case 'add-member': {
        const listId = parsed.positional[0];
        const email = parsed.positional[1];
        if (!listId || !email) {
          console.error('Error: List ID and email required');
          console.error('Usage: mailchimp add-member <listId> <email> --dc <dc>');
          process.exit(1);
        }

        const memberData = {
          email: email,
          status: parsed.options.status || parsed.options.s || 'subscribed',
        };

        if (parsed.options.fname || parsed.options.lname) {
          memberData.mergeFields = {};
          if (parsed.options.fname) memberData.mergeFields.FNAME = parsed.options.fname;
          if (parsed.options.lname) memberData.mergeFields.LNAME = parsed.options.lname;
        }

        if (parsed.options.tags) {
          memberData.tags = parsed.options.tags.split(',').map(t => t.trim());
        }

        const result = client.addMember(listId, memberData);
        console.log(`Added: ${result.email_address} (${result.status})`);
        console.log(JSON.stringify(MailchimpClient.formatMember(result), null, 2));
        break;
      }

      case 'search': {
        const query = parsed.positional[0];
        if (!query) {
          console.error('Error: Search query required');
          console.error('Usage: mailchimp search <query> --dc <dc>');
          process.exit(1);
        }

        const result = client.searchMembers(query);
        const members = result.exact_matches?.members || [];
        const fullSearch = result.full_search?.members || [];
        const allMembers = [...members, ...fullSearch];

        if (parsed.options.summary) {
          console.log(`Found ${allMembers.length} match(es):\n`);
          for (const member of allMembers) {
            const formatted = MailchimpClient.formatMember(member);
            console.log(`${formatted.email} - ${formatted.fullName || '(no name)'}`);
            console.log(`  Status: ${formatted.status} | List: ${formatted.listId}`);
          }
        } else {
          const formatted = allMembers.map(m => MailchimpClient.formatMember(m));
          console.log(JSON.stringify({ members: formatted, total: allMembers.length }, null, 2));
        }
        break;
      }

      case 'campaigns': {
        const result = client.getCampaigns({
          count: parseInt(parsed.options.count || parsed.options.n || '10'),
          offset: parseInt(parsed.options.offset || '0'),
          status: parsed.options.status || parsed.options.s,
          type: parsed.options.type || parsed.options.t,
          since: parsed.options.since,
          before: parsed.options.before,
        });

        if (parsed.options.summary) {
          console.log(`Found ${result.total_items} campaign(s):\n`);
          for (const campaign of result.campaigns) {
            const formatted = MailchimpClient.formatCampaign(campaign);
            console.log(`${formatted.title}`);
            console.log(`  Subject: ${formatted.subject}`);
            console.log(`  Status: ${formatted.status} | Type: ${formatted.type}`);
            console.log(`  Sent: ${formatted.sendTime || 'Not sent'}`);
            if (formatted.status === 'sent') {
              console.log(`  Emails: ${formatted.emailsSent} | Opens: ${formatted.uniqueOpens} (${(formatted.openRate * 100).toFixed(1)}%) | Clicks: ${formatted.subscriberClicks} (${(formatted.clickRate * 100).toFixed(1)}%)`);
            }
            console.log(`  ID: ${formatted.id}`);
            console.log('');
          }
        } else {
          const formatted = result.campaigns.map(c => MailchimpClient.formatCampaign(c));
          console.log(JSON.stringify({ campaigns: formatted, total: result.total_items }, null, 2));
        }
        break;
      }

      case 'campaign': {
        const campaignId = parsed.positional[0];
        if (!campaignId) {
          console.error('Error: Campaign ID required');
          console.error('Usage: mailchimp campaign <campaignId> --dc <dc>');
          process.exit(1);
        }

        const campaign = client.getCampaign(campaignId);

        if (parsed.options.summary) {
          const formatted = MailchimpClient.formatCampaign(campaign);
          console.log(`Title: ${formatted.title}`);
          console.log(`Subject: ${formatted.subject}`);
          console.log(`Preview: ${formatted.previewText || '(none)'}`);
          console.log(`From: ${formatted.fromName}`);
          console.log(`Reply To: ${formatted.replyTo}`);
          console.log(`Status: ${formatted.status}`);
          console.log(`Type: ${formatted.type}`);
          console.log(`List: ${formatted.listName} (${formatted.listId})`);
          console.log(`Created: ${formatted.createTime}`);
          console.log(`Sent: ${formatted.sendTime || 'Not sent'}`);
          if (formatted.status === 'sent') {
            console.log(`Emails Sent: ${formatted.emailsSent}`);
            console.log(`Opens: ${formatted.uniqueOpens} (${(formatted.openRate * 100).toFixed(1)}%)`);
            console.log(`Clicks: ${formatted.subscriberClicks} (${(formatted.clickRate * 100).toFixed(1)}%)`);
          }

          if (parsed.options.content) {
            const content = client.getCampaignContent(campaignId);
            console.log('\n--- HTML Content ---\n');
            console.log(content.html || '(no HTML content)');
          }
        } else {
          const result = { campaign: MailchimpClient.formatCampaign(campaign) };
          if (parsed.options.content) {
            result.content = client.getCampaignContent(campaignId);
          }
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }

      case 'report': {
        const campaignId = parsed.positional[0];
        if (!campaignId) {
          console.error('Error: Campaign ID required');
          console.error('Usage: mailchimp report <campaignId> --dc <dc>');
          process.exit(1);
        }

        const report = client.getCampaignReport(campaignId);

        if (parsed.options.summary) {
          console.log(`Campaign: ${report.campaign_title}`);
          console.log(`Subject: ${report.subject_line}`);
          console.log(`List: ${report.list_name}`);
          console.log(`Sent: ${report.send_time}`);
          console.log('');
          console.log('--- Performance ---');
          console.log(`Emails Sent: ${report.emails_sent}`);
          console.log(`Opens: ${report.opens?.unique_opens || 0} unique (${((report.opens?.open_rate || 0) * 100).toFixed(1)}%)`);
          console.log(`Clicks: ${report.clicks?.unique_clicks || 0} unique (${((report.clicks?.click_rate || 0) * 100).toFixed(1)}%)`);
          console.log(`Bounces: ${report.bounces?.hard_bounces || 0} hard, ${report.bounces?.soft_bounces || 0} soft`);
          console.log(`Unsubscribes: ${report.unsubscribed || 0}`);
          console.log(`Abuse Reports: ${report.abuse_reports || 0}`);

          if (parsed.options.clicks) {
            const clickDetails = client.getCampaignClickDetails(campaignId);
            console.log('\n--- Click Details ---');
            for (const link of (clickDetails.urls_clicked || [])) {
              console.log(`${link.url}`);
              console.log(`  Clicks: ${link.total_clicks} (${link.unique_clicks} unique)`);
            }
          }

          if (parsed.options.opens) {
            const openDetails = client.getCampaignOpenDetails(campaignId, { count: 20 });
            console.log('\n--- Recent Opens ---');
            for (const open of (openDetails.members || [])) {
              console.log(`${open.email_address} - ${open.opens_count} opens`);
            }
          }
        } else {
          const result = { report };
          if (parsed.options.clicks) {
            result.clickDetails = client.getCampaignClickDetails(campaignId);
          }
          if (parsed.options.opens) {
            result.openDetails = client.getCampaignOpenDetails(campaignId);
          }
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }

      case 'tags': {
        const listId = parsed.positional[0];
        if (!listId) {
          console.error('Error: List ID required');
          console.error('Usage: mailchimp tags <listId> --dc <dc>');
          process.exit(1);
        }

        const result = client.getTags(listId);

        if (parsed.options.summary) {
          console.log(`Found ${result.total_items} tag(s):\n`);
          for (const tag of result.segments) {
            console.log(`${tag.name} (${tag.member_count} members)`);
            console.log(`  ID: ${tag.id}`);
          }
        } else {
          const tags = result.segments.map(t => ({
            id: t.id,
            name: t.name,
            memberCount: t.member_count,
            createdAt: t.created_at,
            updatedAt: t.updated_at,
          }));
          console.log(JSON.stringify({ tags, total: result.total_items }, null, 2));
        }
        break;
      }

      case 'automations': {
        const result = client.getAutomations();

        if (parsed.options.summary) {
          console.log(`Found ${result.total_items} automation(s):\n`);
          for (const auto of result.automations) {
            console.log(`${auto.settings?.title || '(no title)'}`);
            console.log(`  Status: ${auto.status}`);
            console.log(`  Emails Sent: ${auto.emails_sent || 0}`);
            console.log(`  ID: ${auto.id}`);
            console.log('');
          }
        } else {
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }

      default:
        console.error(`Error: Unknown command '${parsed.command}'`);
        console.error('\nRun: mailchimp help');
        process.exit(1);
    }

  } catch (error) {
    if (parsed.options.summary) {
      console.error(`Mailchimp Error: ${error.message}`);
    } else {
      console.error(JSON.stringify({
        error: error.message,
        status: error.status,
        type: error.type,
        data: error.data
      }, null, 2));
    }
    process.exit(1);
  }
}

// Execute
main();

module.exports = { MailchimpClient, md5 };
