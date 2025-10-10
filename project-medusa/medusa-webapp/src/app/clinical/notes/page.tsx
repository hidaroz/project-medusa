'use client';

import { useState } from 'react';
import Layout from '@/components/Layout';

interface ClinicalNote {
  id: string;
  patientId: string;
  patientName: string;
  noteType: 'Progress Note' | 'Consultation' | 'Discharge Summary' | 'Procedure Note';
  author: string;
  date: string;
  time: string;
  status: 'Draft' | 'Signed' | 'Amended';
  content: string;
}

const mockNotes: ClinicalNote[] = [
  {
    id: 'N001',
    patientId: 'P001',
    patientName: 'Sarah Johnson',
    noteType: 'Progress Note',
    author: 'Dr. Emily Chen',
    date: '2024-10-15',
    time: '10:30 AM',
    status: 'Signed',
    content: 'Patient reports improved blood glucose control with current medication regimen. Blood pressure well controlled. Continue current medications. Follow up in 3 months.'
  },
  {
    id: 'N002',
    patientId: 'P002',
    patientName: 'Robert Martinez',
    noteType: 'Consultation',
    author: 'Dr. James Wilson',
    date: '2024-10-14',
    time: '2:15 PM',
    status: 'Signed',
    content: 'Patient presents with worsening asthma symptoms. Peak flow decreased from baseline. Increased albuterol use. Consider step-up therapy.'
  },
  {
    id: 'N003',
    patientId: 'P004',
    patientName: 'James Williams',
    noteType: 'Procedure Note',
    author: 'Dr. Robert Davis',
    date: '2024-10-13',
    time: '9:45 AM',
    status: 'Signed',
    content: 'Cardiac catheterization performed. No significant coronary artery disease. Left ventricular function normal. Continue current cardiac medications.'
  }
];

export default function ClinicalNotesPage() {
  const [selectedNote, setSelectedNote] = useState<ClinicalNote | null>(null);
  const [filter, setFilter] = useState<'all' | 'draft' | 'signed' | 'amended'>('all');

  const filteredNotes = mockNotes.filter(note => 
    filter === 'all' || note.status.toLowerCase() === filter
  );

  return (
    <Layout>
      <div className="p-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-white mb-2">Clinical Notes</h2>
          <p className="text-slate-400">View and manage clinical documentation</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Notes List */}
          <div className="lg:col-span-1">
            <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-white">Recent Notes</h3>
                <button className="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm transition">
                  New Note
                </button>
              </div>

              {/* Filter */}
              <div className="mb-4">
                <select
                  value={filter}
                  onChange={(e) => setFilter(e.target.value as 'all' | 'draft' | 'signed' | 'amended')}
                  className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-white text-sm"
                >
                  <option value="all">All Notes</option>
                  <option value="draft">Draft</option>
                  <option value="signed">Signed</option>
                  <option value="amended">Amended</option>
                </select>
              </div>

              {/* Notes List */}
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {filteredNotes.map((note) => (
                  <div
                    key={note.id}
                    onClick={() => setSelectedNote(note)}
                    className={`p-3 rounded-lg cursor-pointer transition ${
                      selectedNote?.id === note.id
                        ? 'bg-blue-600/20 border border-blue-600/50'
                        : 'bg-slate-900 hover:bg-slate-700'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="text-sm font-medium text-white">{note.patientName}</div>
                        <div className="text-xs text-slate-400">{note.noteType}</div>
                        <div className="text-xs text-slate-500">{note.date} {note.time}</div>
                      </div>
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        note.status === 'Signed' 
                          ? 'bg-green-600/20 text-green-400 border border-green-600/50'
                          : note.status === 'Draft'
                          ? 'bg-yellow-600/20 text-yellow-400 border border-yellow-600/50'
                          : 'bg-red-600/20 text-red-400 border border-red-600/50'
                      }`}>
                        {note.status}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Note Detail */}
          <div className="lg:col-span-2">
            {selectedNote ? (
              <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
                <div className="flex items-start justify-between mb-6">
                  <div>
                    <h3 className="text-xl font-bold text-white mb-2">{selectedNote.patientName}</h3>
                    <div className="flex items-center space-x-4 text-sm text-slate-400">
                      <span>{selectedNote.noteType}</span>
                      <span>•</span>
                      <span>{selectedNote.date} {selectedNote.time}</span>
                      <span>•</span>
                      <span>{selectedNote.author}</span>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className={`px-3 py-1 text-sm rounded-full ${
                      selectedNote.status === 'Signed' 
                        ? 'bg-green-600/20 text-green-400 border border-green-600/50'
                        : selectedNote.status === 'Draft'
                        ? 'bg-yellow-600/20 text-yellow-400 border border-yellow-600/50'
                        : 'bg-red-600/20 text-red-400 border border-red-600/50'
                    }`}>
                      {selectedNote.status}
                    </span>
                    <button className="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm transition">
                      Edit
                    </button>
                  </div>
                </div>

                <div className="bg-slate-900 rounded-lg p-4">
                  <h4 className="text-sm font-medium text-slate-300 mb-3">Note Content</h4>
                  <div className="text-slate-300 whitespace-pre-wrap leading-relaxed">
                    {selectedNote.content}
                  </div>
                </div>

                <div className="mt-6 pt-4 border-t border-slate-700">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-slate-400">Patient ID:</span>
                      <span className="text-white ml-2">{selectedNote.patientId}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Note ID:</span>
                      <span className="text-white ml-2">{selectedNote.id}</span>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 flex items-center justify-center h-64">
                <div className="text-center">
                  <svg className="w-12 h-12 text-slate-500 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  <p className="text-slate-400">Select a note to view details</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}
