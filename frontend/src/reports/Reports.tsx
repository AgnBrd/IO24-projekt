import * as React from 'react';
import Paper from '@mui/material/Paper';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TablePagination from '@mui/material/TablePagination';
import TableRow from '@mui/material/TableRow';
import { ReactComponent as GoBack } from "../images/back.svg";
import logo from "../images/Logo3.svg";
import './Reports.css';
import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Button } from "@mui/material";

interface Column {
    id: keyof Data;
    label: string;
    minWidth?: number;
    align?: 'center';
    format?: (value: any) => string;
}

const columns: readonly Column[] = [
    { id: 'id', label: 'Reports id', minWidth: 170 },
    { id: 'patient_id', label: 'Patients id', minWidth: 170, align: 'center' },
    { id: 'date', label: 'Date', minWidth: 100, align: 'center' },
    {
        id: 'difference_mouth',
        label: 'Difference mouth',
        minWidth: 170,
        align: 'center',
        format: (value: string) => value,
    },
    {
        id: 'difference_2',
        label: 'Difference eyebrow',
        minWidth: 170,
        align: 'center',
        format: (value: string) => value,
    },
];

interface Data {
    patient_id: number;
    id: number;
    date: string;
    difference_mouth: number;
    difference_2: number;
}

export default function Reports() {

    const navigate = useNavigate();
    const [page, setPage] = React.useState(0);
    const [rowsPerPage, setRowsPerPage] = React.useState(10);
    const [error, setError] = useState<string | null>(null);
    const location = useLocation();
    const params = new URLSearchParams(location.search);
    const patientId = params.get('patientId');
    const [rows, setRows] = useState<Data[]>([]);

    const handleChangePage = (event: unknown, newPage: number) => {
        setPage(newPage);
    };

    const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
        setRowsPerPage(+event.target.value);
        setPage(0);
    };

    const handleGoBack = () => {
        navigate(-1);
    };

    const handleGenerateReport = async () => {
        if (!patientId) {
            setError('Patient ID is not specified.');
            return;
        }

        try {
            const response = await fetch("http://localhost:8000/create-report_doc/", {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify({patient_id: patientId})
            });

            if (!response.ok) {
                throw new Error('Failed to generate report');
            }

            const result = await response.json();
            console.log(result.message);

            // If success, handle success message or action
        } catch (error) {
            console.error('Error generating report:', error);
            setError('Error generating report. Please try again.');
        }
    };

    useEffect(() => {
        if (patientId) {
            fetchReports();
        }
    }, [patientId]);

    const fetchReports = async () => {
    try {
        const response = await fetch(`http://localhost:8000/reports/doctor/${patientId}/`, {  // Note the trailing slash here
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
        });

        if (!response.ok) {
            throw new Error('Failed to fetch reports');
        }

        const data = await response.json();
        setRows(data);
    } catch (error: any) {
        setError(error.message);
    }
};


    return (
        <div className="background_reports">
            <header className="header_reports">REPORTS</header>
            <img src={logo} alt="Logo" className="logo_bottom" />
            <button className="go-back" onClick={handleGoBack}>
                <GoBack />
                <span>Go back</span>
            </button>
            <div className="table-container-wrapper">
                <Paper sx={{ width: '100%', overflow: 'hidden' }}>
                    <TableContainer className="table-container" sx={{ maxHeight: 440 }}>
                        <Table stickyHeader aria-label="sticky table" className="table">
                            <TableHead>
                                <TableRow className="table-header">
                                    {columns.map((column, index) => (
                                        <TableCell
                                            key={column.id}
                                            align={index === 0 ? 'center' : column.align}
                                            style={{ minWidth: column.minWidth }}
                                            className={`no-bottom-border`}
                                        >
                                            <b>{column.label}</b>
                                        </TableCell>
                                    ))}
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {rows
                                    .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                                    .map((row, rowIndex) => (
                                        <TableRow hover role="checkbox" tabIndex={-1} key={rowIndex}>
                                            {columns.map((column) => {
                                                const value = row[column.id as keyof Data];
                                                return (
                                                    <TableCell key={column.id} align="center"
                                                        className="no-bottom-border">
                                                        {column.format && typeof value !== 'undefined' ? column.format(value) : value}
                                                    </TableCell>
                                                );
                                            })}
                                        </TableRow>
                                    ))}
                            </TableBody>
                        </Table>
                    </TableContainer>
                    <TablePagination
                        rowsPerPageOptions={[10, 25, 100]}
                        component="div"
                        count={rows.length}
                        rowsPerPage={rowsPerPage}
                        page={page}
                        onPageChange={handleChangePage}
                        onRowsPerPageChange={handleChangeRowsPerPage}
                    />

                    <div className="button-container">
                        <Button variant="contained" type="submit" onClick={handleGenerateReport}>
                            Generate summary report
                        </Button>
                    </div>

                </Paper>
            </div>
        </div>
    );
}
