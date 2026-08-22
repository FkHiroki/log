import crypto from 'node:crypto';

export const config = { api: { bodyParser: false } }; // Disable bodyParser for Slack signature verification

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).send('Method Not Allowed');
    return;
  }

  const rawBody = await readRawBody(req);
  const timestamp = req.headers['x-slack-request-timestamp'];
  const signature = req.headers['x-slack-signature'];

  if (!verifySlackSignature(rawBody, timestamp, signature, process.env.SLACK_SIGNING_SECRET)) {
    res.status(401).send('invalid signature');
    return;
  }

  const body = JSON.parse(rawBody); // extract the JSON body after signature verification

  // Initial URL verification from Slack
  if (body.type === 'url_verification') {
    res.status(200).json({ challenge: body.challenge });
    return;
  }

  if (body.type !== 'event_callback') {
    res.status(200).send('ok');
    return;
  }

  // Slack retries delivery on slow/failed responses; the first attempt already committed (or is committing), so retries are just ignored.
  if (req.headers['x-slack-retry-num']) {
    res.status(200).send('ok');
    return;
  }

  const event = body.event;
  const shouldProcess =
    event &&
    event.type === 'message' &&
    !event.subtype &&
    !event.bot_id &&
    event.channel === process.env.SLACK_CHANNEL_ID &&
    typeof event.text === 'string' &&
    event.text.trim().length > 0;

  if (!shouldProcess) {
    res.status(200).send('ok');
    return;
  }

  try {
    await appendDiaryEntry(event);
    if (process.env.SLACK_BOT_TOKEN) {
      await addReaction(event.channel, event.ts);
    }
  } catch (err) {
    // Respond 200 regardless so Slack doesn't hammer retries; surface the
    // failure in Vercel logs for manual follow-up instead.
    console.error('failed to append diary entry', err);
  }

  res.status(200).send('ok');
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function verifySlackSignature(rawBody, timestamp, signature, secret) {
  if (!timestamp || !signature || !secret) return false;

  const age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (Number.isNaN(age) || age > 60 * 5) return false;

  const expected = `v0=${crypto
    .createHmac('sha256', secret)
    .update(`v0:${timestamp}:${rawBody}`, 'utf8')
    .digest('hex')}`;

  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length) return false;
  return crypto.timingSafeEqual(sigBuf, expBuf);
}

function toJstDateString(slackTs) {
  const date = new Date(Number(slackTs) * 1000);
  const formatted = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Tokyo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(date);
  return formatted.replaceAll('-', '/');
}

async function appendDiaryEntry(event) {
  const dateStr = toJstDateString(event.ts);
  const text = event.text.trim();

  const repo = process.env.GITHUB_REPO;
  const branch = process.env.GITHUB_BRANCH || 'main';
  const token = process.env.GITHUB_TOKEN;
  const path = 'README.md';

  const getRes = await fetch(`https://api.github.com/repos/${repo}/contents/${path}?ref=${branch}`, {
    headers: githubHeaders(token),
  });
  if (!getRes.ok) {
    throw new Error(`failed to fetch README.md: ${getRes.status} ${await getRes.text()}`);
  }
  const file = await getRes.json();
  const content = Buffer.from(file.content, 'base64').toString('utf-8');
  const updated = mergeEntry(content, dateStr, text);

  const putRes = await fetch(`https://api.github.com/repos/${repo}/contents/${path}`, {
    method: 'PUT',
    headers: githubHeaders(token),
    body: JSON.stringify({
      message: `diary: ${dateStr}`,
      content: Buffer.from(updated, 'utf-8').toString('base64'),
      sha: file.sha,
      branch,
    }),
  });
  if (!putRes.ok) {
    throw new Error(`failed to update README.md: ${putRes.status} ${await putRes.text()}`);
  }
}

function githubHeaders(token) {
  return {
    Authorization: `token ${token}`,
    Accept: 'application/vnd.github+json',
    'Content-Type': 'application/json',
    'User-Agent': 'log-diary-bot',
  };
}

async function addReaction(channel, timestamp) {
  await fetch('https://slack.com/api/reactions.add', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.SLACK_BOT_TOKEN}`,
      'Content-Type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({ channel, timestamp, name: 'white_check_mark' }),
  });
}

// Inserts a diary paragraph into the README.
// - Existing `## {dateStr}` heading -> append the paragraph under it.
// - New date -> insert a new heading right before the first existing heading.
export function mergeEntry(content, dateStr, text) {
  const lines = content.split('\n');
  const headingIndices = [];
  lines.forEach((line, i) => {
    if (line.startsWith('## ')) headingIndices.push(i);
  });

  if (headingIndices.length === 0) {
    const trimmed = content.replace(/\s+$/, '');
    return `${trimmed}\n\n## ${dateStr}\n${text}\n`;
  }

  const targetIdx = headingIndices.find((i) => lines[i] === `## ${dateStr}`);

  if (targetIdx !== undefined) {
    const nextIdx = headingIndices.find((i) => i > targetIdx) ?? lines.length;
    let insertPos = nextIdx;
    while (insertPos > targetIdx + 1 && lines[insertPos - 1].trim() === '') insertPos--;
    const newLines = [...lines.slice(0, insertPos), '', text, ...lines.slice(insertPos)];
    return newLines.join('\n');
  }

  const insertAt = headingIndices[0];
  const newSection = [`## ${dateStr}`, text, ''];
  const newLines = [...lines.slice(0, insertAt), ...newSection, ...lines.slice(insertAt)];
  return newLines.join('\n');
}
